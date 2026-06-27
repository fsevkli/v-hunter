"""Tests for hunter.context.build_poc_context."""
import textwrap
from pathlib import Path

import pytest

from hunter.context import (
    _find_enclosing_function,
    _enclosing_function_name,
    build_poc_context,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, filename: str, content: str) -> Path:
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _find_enclosing_function
# ---------------------------------------------------------------------------

def test_finds_simple_function():
    lines = [
        "<?php",
        "function foo() {",
        "    $x = 1;",
        "    return $x;",
        "}",
    ]
    start, end = _find_enclosing_function(lines, 3)
    assert start == 2
    assert end == 5


def test_finds_method_in_class():
    lines = [
        "<?php class Foo {",
        "    public function bar() {",
        "        $y = 2;",       # target line 3
        "    }",
        "}",
    ]
    start, end = _find_enclosing_function(lines, 3)
    assert start == 2
    assert end == 4


def test_nested_braces_counted_correctly():
    lines = [
        "function outer() {",
        "    if (true) {",
        "        echo 'hi';",   # target line 3
        "    }",
        "}",
    ]
    start, end = _find_enclosing_function(lines, 3)
    assert start == 1
    assert end == 5


def test_returns_none_when_no_function():
    lines = ["<?php", "$x = 1;", "$y = 2;"]
    assert _find_enclosing_function(lines, 2) is None


def test_target_on_function_definition_line():
    lines = [
        "function baz() {",   # target = line 1
        "    return 42;",
        "}",
    ]
    start, end = _find_enclosing_function(lines, 1)
    assert start == 1
    assert end == 3


# ---------------------------------------------------------------------------
# _enclosing_function_name
# ---------------------------------------------------------------------------

def test_extracts_function_name():
    lines = [
        "function my_handler() {",
        "    $x = $_POST['val'];",   # target = 2
        "}",
    ]
    assert _enclosing_function_name(lines, 2) == "my_handler"


def test_extracts_method_name():
    lines = [
        "class Foo {",
        "    public function do_ajax() {",
        "        $wpdb->query('...');",   # target = 3
        "    }",
        "}",
    ]
    assert _enclosing_function_name(lines, 3) == "do_ajax"


# ---------------------------------------------------------------------------
# build_poc_context — integration
# ---------------------------------------------------------------------------

PHP_CLASS = """\
    <?php
    class MyPlugin {
        function __construct() {
            add_action('wp_ajax_my_action', array($this, 'my_handler'));
            add_action('wp_ajax_nopriv_my_action', array($this, 'my_handler'));
        }

        function my_handler() {
            $nonce = $_REQUEST['_wpnonce'];
            wp_verify_nonce($nonce, 'my_action_nonce');
            global $wpdb;
            $id = $_POST['id'];
            $wpdb->get_var("SELECT * FROM wp_table WHERE id = $id");
        }
    }
"""

def _make_plugin(tmp_path: Path) -> tuple[Path, dict]:
    plugin_dir = tmp_path / "myplugin"
    plugin_dir.mkdir()
    php_file = plugin_dir / "class.myplugin.php"
    php_file.write_text(textwrap.dedent(PHP_CLASS), encoding="utf-8")

    candidate = {
        "file_path":    "class.myplugin.php",
        "line_start":   13,
        "line_end":     13,
        "rule_id":      "wp-sqli",
        "code_snippet": '$wpdb->get_var("SELECT * FROM wp_table WHERE id = $id");',
    }
    return plugin_dir, candidate


def test_build_poc_context_contains_snippet(tmp_path):
    plugin_dir, candidate = _make_plugin(tmp_path)
    ctx = build_poc_context(plugin_dir, candidate)
    assert "Semgrep Flagged Snippet" in ctx
    assert candidate["code_snippet"] in ctx


def test_build_poc_context_contains_enclosing_function(tmp_path):
    plugin_dir, candidate = _make_plugin(tmp_path)
    ctx = build_poc_context(plugin_dir, candidate)
    assert "Enclosing Function" in ctx
    assert "my_handler" in ctx


def test_build_poc_context_contains_ajax_registration(tmp_path):
    plugin_dir, candidate = _make_plugin(tmp_path)
    ctx = build_poc_context(plugin_dir, candidate)
    assert "Entry-Point Registrations" in ctx
    assert "wp_ajax_my_action" in ctx


def test_build_poc_context_contains_nonce_section(tmp_path):
    plugin_dir, candidate = _make_plugin(tmp_path)
    ctx = build_poc_context(plugin_dir, candidate)
    assert "Nonce" in ctx
    assert "wp_verify_nonce" in ctx


def test_build_poc_context_missing_file_returns_snippet_only(tmp_path):
    plugin_dir = tmp_path / "empty_plugin"
    plugin_dir.mkdir()
    candidate = {
        "file_path":    "nonexistent.php",
        "line_start":   1,
        "line_end":     1,
        "rule_id":      "wp-sqli",
        "code_snippet": "$wpdb->query($x);",
    }
    ctx = build_poc_context(plugin_dir, candidate)
    assert "Semgrep Flagged Snippet" in ctx
    assert "$wpdb->query($x);" in ctx


def test_build_poc_context_respects_char_cap(tmp_path):
    plugin_dir = tmp_path / "bigplugin"
    plugin_dir.mkdir()
    # Write a file with a huge function
    big = "<?php\nfunction huge() {\n" + ("    $x = 1;\n" * 5000) + "}\n"
    (plugin_dir / "big.php").write_text(big, encoding="utf-8")
    candidate = {
        "file_path":    "big.php",
        "line_start":   100,
        "line_end":     100,
        "rule_id":      "wp-sqli",
        "code_snippet": "$x = 1;",
    }
    ctx = build_poc_context(plugin_dir, candidate)
    assert len(ctx) <= 24_500  # some slack for the truncation suffix


def test_registration_matched_by_enclosing_function_name(tmp_path):
    """Registration in a different file is found via the callback name."""
    plugin_dir = tmp_path / "plugin2"
    plugin_dir.mkdir()

    # Main file with registration
    main_php = "<?php\nadd_action('wp_ajax_do_stuff', 'vulnerable_func');\n"
    (plugin_dir / "main.php").write_text(main_php, encoding="utf-8")

    # Separate file with the vulnerable function
    vuln_php = (
        "<?php\n"
        "function vulnerable_func() {\n"
        "    global $wpdb;\n"
        "    $wpdb->query($_POST['q']);\n"
        "}\n"
    )
    (plugin_dir / "vuln.php").write_text(vuln_php, encoding="utf-8")

    candidate = {
        "file_path":    "vuln.php",
        "line_start":   4,
        "line_end":     4,
        "rule_id":      "wp-sqli",
        "code_snippet": "$wpdb->query($_POST['q']);",
    }
    ctx = build_poc_context(plugin_dir, candidate)
    assert "wp_ajax_do_stuff" in ctx
