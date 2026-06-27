"""
Tests for helpers introduced during the cross-function tracing / pre-filter /
brace-counting / dedup / coverage / escalation session.

Pins behavior on the load-bearing infrastructure so silent regressions can't
turn FPs into "confirmed" CVEs or hide real findings.
"""
import os
import tempfile
import textwrap
import unittest
from pathlib import Path


# ---------------------------------------------------------------------------
# _mask_php: PHP token masker (strings, comments, heredocs, template HTML)
# ---------------------------------------------------------------------------

class TestPhpMasker(unittest.TestCase):
    def setUp(self):
        from hunter.context import _mask_php, _scan_functions
        self.mask = _mask_php
        self.scan = _scan_functions

    def test_string_literal_braces_are_masked(self):
        src = '<?php function f() { $x = "}"; }'
        masked = self.mask(src)
        # The `}` inside the string must not survive — otherwise the brace
        # counter would close the function prematurely.
        outer_close = masked.rindex("}")
        # The masked text's only remaining `}` should be the function's own.
        self.assertEqual(masked.count("}"), 1)
        self.assertEqual(masked.count("{"), 1)

    def test_block_comment_braces_are_masked(self):
        src = '<?php /* end } */ function f() { return 1; }'
        masked = self.mask(src)
        # `}` inside the block comment is replaced; only the real one remains
        self.assertEqual(masked.count("}"), 1)
        self.assertNotIn("end } ", masked)

    def test_heredoc_braces_are_masked(self):
        src = (
            '<?php\n'
            'function f() {\n'
            '    $html = <<<HTML\n'
            '<div>{$x}</div>\n'
            'HTML;\n'
            '    return 1;\n'
            '}\n'
        )
        masked = self.mask(src)
        # `{$x}` inside the heredoc should not contribute to brace counting
        self.assertEqual(masked.count("{"), 1)  # only the function's `{`
        self.assertEqual(masked.count("}"), 1)  # only the function's `}`

    def test_html_between_php_tags_is_masked(self):
        src = (
            '<?php function f() {\n'
            '?>\n'
            '<div>}</div>\n'
            '<?php return 1; }\n'
        )
        masked = self.mask(src)
        # The `}` inside the HTML chunk must be masked
        self.assertEqual(masked.count("}"), 1)

    def test_newlines_preserved(self):
        src = '<?php /* line1\nline2\nline3 */ $x = 1;'
        masked = self.mask(src)
        self.assertEqual(masked.count("\n"), src.count("\n"))

    def test_php_keyword_inside_string_is_masked(self):
        src = '<?php $x = "function foo(){}"; function real() {}'
        masked = self.mask(src)
        # The literal `function` inside the string should not be picked up by
        # the function scanner; only `function real` should appear.
        functions = self.scan(masked)
        self.assertEqual(len(functions), 1)


# ---------------------------------------------------------------------------
# _scan_functions + _find_enclosing_function: scope detection
# ---------------------------------------------------------------------------

class TestFunctionScanning(unittest.TestCase):
    def setUp(self):
        from hunter.context import (
            _scan_functions, _mask_php,
            _find_enclosing_function, _enclosing_function_name,
        )
        self.scan          = _scan_functions
        self.mask          = _mask_php
        self.find_bounds   = _find_enclosing_function
        self.find_name     = _enclosing_function_name

    def test_same_line_opening_brace(self):
        """Regression: the old backward-walk algorithm failed on
        `function foo() { ... }` one-liners."""
        src = '<?php\nfunction same_line() { return 1; }\n'
        bounds = self.find_bounds(src.splitlines(), 2)
        self.assertEqual(bounds, (2, 2))

    def test_separate_line_opening_brace(self):
        src = '<?php\nfunction sep()\n{\n    return 1;\n}\n'
        bounds = self.find_bounds(src.splitlines(), 4)
        self.assertEqual(bounds, (2, 5))

    def test_innermost_function_wins(self):
        src = (
            '<?php\n'
            'class Container {\n'
            '    public function outer() {\n'
            '        $cb = function() {\n'
            '            return 1;\n'
            '        };\n'
            '        return $cb();\n'
            '    }\n'
            '}\n'
        )
        # Target is line 5 (inside the closure). Closures are anonymous so the
        # ENCLOSING NAMED function is `outer`, which is what we want.
        name = self.find_name(src.splitlines(), 5)
        self.assertEqual(name, "outer")

    def test_function_inside_heredoc_not_matched(self):
        src = (
            '<?php\n'
            '$x = <<<EOT\n'
            'function fake() { ... }\n'
            'EOT;\n'
            'function real() {\n'
            '    return 1;\n'
            '}\n'
        )
        masked = self.mask(src)
        funcs = self.scan(masked)
        names = [src.splitlines()[s - 1] for s, _ in funcs]
        # Only `function real` should be picked up.
        self.assertEqual(len(funcs), 1)
        self.assertIn("real", names[0])


# ---------------------------------------------------------------------------
# Dedup helpers: _norm_rule, _is_in_same_dedup_group, _location_key
# ---------------------------------------------------------------------------

class TestDedupHelpers(unittest.TestCase):
    def setUp(self):
        from hunter.static_filter import (
            _norm_rule, _is_in_same_dedup_group, _location_key,
        )
        self.norm   = _norm_rule
        self.same   = _is_in_same_dedup_group
        self.loc    = _location_key

    def test_norm_strips_precise_suffix(self):
        self.assertEqual(self.norm("wp-foo-precise"), "wp-foo")
        self.assertEqual(self.norm("wp-bar"), "wp-bar")
        self.assertEqual(self.norm("rules.wp-baz-precise"), "wp-baz")
        self.assertEqual(self.norm("namespace.x.wp-quux"), "wp-quux")

    def test_dedup_group_membership_with_normalization(self):
        # wp-missing-nonce-check and wp-nopriv-missing-nonce are in the same
        # group; -precise suffix shouldn't matter.
        self.assertTrue(self.same(
            "wp-missing-nonce-check-precise", "wp-nopriv-missing-nonce"
        ))
        self.assertTrue(self.same(
            "rules.wp-missing-nonce-check-precise", "wp-nopriv-missing-nonce"
        ))

    def test_dedup_excludes_same_rule(self):
        # Same-rule dedup is handled elsewhere (exact (rule, file, range) key),
        # not by this group-based check.
        self.assertFalse(self.same(
            "wp-missing-nonce-check", "wp-missing-nonce-check"
        ))

    def test_dedup_excludes_unrelated_rules(self):
        self.assertFalse(self.same("wp-sqli", "wp-reflected-xss-precise"))
        self.assertFalse(self.same("wp-sqli", "wp-sqli-prepare-concat"))

    def test_location_key_drops_line_end(self):
        """Near-overlap should match even when sibling rules disagree on
        line_end."""
        k1 = self.loc("plugin", "a.php", 42)
        k2 = self.loc("plugin", "a.php", 42)
        self.assertEqual(k1, k2)
        # Different start line -> different key
        self.assertNotEqual(k1, self.loc("plugin", "a.php", 43))


# ---------------------------------------------------------------------------
# pre_filter: balanced-call extractor, arg splitting, literal resolution
# ---------------------------------------------------------------------------

class TestPreFilterHelpers(unittest.TestCase):
    def setUp(self):
        from hunter.pre_filter import (
            _extract_balanced_call, _split_call_args, _resolve_to_literal,
        )
        self.extract  = _extract_balanced_call
        self.split    = _split_call_args
        self.resolve  = _resolve_to_literal

    def test_balanced_call_single_line(self):
        text = "add_action('hook', 'cb');"
        # open_pos must point at `(`
        open_pos = text.index("(")
        result = self.extract(text, open_pos)
        self.assertEqual(result, "('hook', 'cb')")

    def test_balanced_call_multi_line(self):
        text = "add_action(\n  'hook',\n  'cb'\n);"
        open_pos = text.index("(")
        result = self.extract(text, open_pos)
        self.assertIn("'hook'", result)
        self.assertIn("'cb'", result)
        self.assertTrue(result.endswith(")"))

    def test_balanced_call_skips_string_parens(self):
        # The `)` inside the string MUST NOT terminate the call early.
        text = "add_action('hook)(' . $x, 'cb');"
        open_pos = text.index("(")
        result = self.extract(text, open_pos)
        self.assertTrue(result.endswith(")"))
        # We should consume the full call up to the real closing paren.
        self.assertIn("'cb'", result)

    def test_split_args_respects_nested_arrays(self):
        # The comma inside the array MUST NOT split the arg list.
        stmt = "('hook', [$this, 'method'])"
        args = self.split(stmt)
        self.assertEqual(len(args), 2)
        self.assertEqual(args[0], "'hook'")
        self.assertTrue(args[1].startswith("[$this"))

    def test_split_args_respects_strings_with_commas(self):
        stmt = "('a,b', 'c,d', 'e')"
        args = self.split(stmt)
        self.assertEqual(args, ["'a,b'", "'c,d'", "'e'"])

    def test_resolve_literal_string(self):
        self.assertEqual(self.resolve("'manage_options'", "", None), "manage_options")
        self.assertEqual(self.resolve('"edit_users"', "", None), "edit_users")

    def test_resolve_variable_to_literal(self):
        file_text = "$cap = 'manage_options';\nadd_menu_page(..., $cap, ...);"
        from pathlib import Path
        # plugin_path can be None when only var resolution is needed (no constants)
        result = self.resolve("$cap", file_text, Path("/nonexistent"))
        self.assertEqual(result, "manage_options")

    def test_resolve_unresolvable_returns_none(self):
        from pathlib import Path
        # No assignment for $foo anywhere
        self.assertIsNone(self.resolve("$foo", "", Path("/nonexistent")))
        # Function-call expressions are not resolved
        self.assertIsNone(self.resolve("get_option('cap')", "", Path("/nonexistent")))
        # $this->prop is intentionally NOT resolved (would need class context)
        self.assertIsNone(self.resolve("$this->cap", "", Path("/nonexistent")))


# ---------------------------------------------------------------------------
# pre_filter: new FP-pattern helpers (custom-cap, nonce-reach, coercion, stale)
# ---------------------------------------------------------------------------


class TestCustomCapAdminOnly(unittest.TestCase):
    """Custom plugin caps (e.g. `cfw_manage_options`) resolved to admin-only."""

    def _make_plugin(self, files: dict[str, str]):
        """Write *files* (path → content) into a fresh tmpdir, return the
        plugin root path. Caller owns cleanup."""
        tmp = tempfile.mkdtemp(prefix="wphunter_test_")
        root = Path(tmp)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(textwrap.dedent(content), encoding="utf-8")
        return root

    def test_pattern_a_role_and_cap_literals(self):
        """`$wp_roles->add_cap('administrator', 'my_cap')` → admin-only."""
        from hunter.pre_filter import _custom_cap_is_admin_only, _CUSTOM_CAP_ADMIN_ONLY
        _CUSTOM_CAP_ADMIN_ONLY.clear()
        root = self._make_plugin({
            "install.php": """<?php
                $wp_roles->add_cap('administrator', 'my_cap');
            """,
        })
        self.assertTrue(_custom_cap_is_admin_only(root, "my_cap"))

    def test_pattern_b_role_variable(self):
        """`$role = get_role('administrator'); $role->add_cap('my_cap')` → admin."""
        from hunter.pre_filter import _custom_cap_is_admin_only, _CUSTOM_CAP_ADMIN_ONLY
        _CUSTOM_CAP_ADMIN_ONLY.clear()
        root = self._make_plugin({
            "install.php": """<?php
                $role = get_role('administrator');
                $role->add_cap('my_cap');
            """,
        })
        self.assertTrue(_custom_cap_is_admin_only(root, "my_cap"))

    def test_pattern_c_foreach_array_loop(self):
        """checkoutwc-lite pattern: literal-array of caps assigned via foreach."""
        from hunter.pre_filter import _custom_cap_is_admin_only, _CUSTOM_CAP_ADMIN_ONLY
        _CUSTOM_CAP_ADMIN_ONLY.clear()
        root = self._make_plugin({
            "Install.php": """<?php
                $capabilities = array(
                    'cfw_manage_pages',
                    'cfw_manage_options',
                );
                foreach ($capabilities as $capability) {
                    $wp_roles->add_cap('administrator', $capability);
                }
            """,
        })
        self.assertTrue(_custom_cap_is_admin_only(root, "cfw_manage_options"))

    def test_rejects_when_subscriber_also_gets_cap(self):
        """If any in-scope role also receives the cap, NOT admin-only."""
        from hunter.pre_filter import _custom_cap_is_admin_only, _CUSTOM_CAP_ADMIN_ONLY
        _CUSTOM_CAP_ADMIN_ONLY.clear()
        root = self._make_plugin({
            "install.php": """<?php
                $wp_roles->add_cap('administrator', 'my_cap');
                $wp_roles->add_cap('subscriber',    'my_cap');
            """,
        })
        self.assertFalse(_custom_cap_is_admin_only(root, "my_cap"))

    def test_unknown_cap_returns_false(self):
        """No add_cap call for the cap → conservative False (let LLM decide)."""
        from hunter.pre_filter import _custom_cap_is_admin_only, _CUSTOM_CAP_ADMIN_ONLY
        _CUSTOM_CAP_ADMIN_ONLY.clear()
        root = self._make_plugin({"empty.php": "<?php // nothing"})
        self.assertFalse(_custom_cap_is_admin_only(root, "ghost_cap"))


class TestHandlerNonceActions(unittest.TestCase):
    def test_extracts_check_ajax_referer(self):
        from hunter.pre_filter import _handler_nonce_actions
        code = "function h() { check_ajax_referer('my_action', 'nonce'); }"
        self.assertEqual(_handler_nonce_actions(code), ["my_action"])

    def test_extracts_wp_verify_nonce(self):
        from hunter.pre_filter import _handler_nonce_actions
        code = "if (wp_verify_nonce($_POST['_wpnonce'], 'foo-bar')) { ... }"
        self.assertEqual(_handler_nonce_actions(code), ["foo-bar"])

    def test_dedups_multiple_calls(self):
        from hunter.pre_filter import _handler_nonce_actions
        code = """
            check_ajax_referer('a', 'nonce');
            wp_verify_nonce($n, 'a');
            check_admin_referer('b');
        """
        self.assertEqual(_handler_nonce_actions(code), ["a", "b"])


class TestNonceCreatorAdminOnly(unittest.TestCase):
    """End-to-end: nonce action's wp_create_nonce sites all admin-context?"""

    def _make_plugin(self, files):
        tmp = tempfile.mkdtemp(prefix="wphunter_test_")
        root = Path(tmp)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(textwrap.dedent(content), encoding="utf-8")
        return root

    def test_admin_enqueue_scripts_only(self):
        """Nonce localized in admin_enqueue_scripts → admin-only."""
        from hunter.pre_filter import (
            _all_nonce_creators_admin_only, _NONCE_ADMIN_ONLY,
        )
        _NONCE_ADMIN_ONLY.clear()
        root = self._make_plugin({
            "admin.php": """<?php
                add_action('admin_enqueue_scripts', function($hook) {
                    if ($hook === 'toplevel_page_x') {
                        wp_localize_script('x', 'X', [
                            'nonce' => wp_create_nonce('plugin_admin_nonce'),
                        ]);
                    }
                });
            """,
        })
        self.assertTrue(_all_nonce_creators_admin_only(root, "plugin_admin_nonce"))

    def test_front_end_shortcode_blocks(self):
        """Nonce also localized inside add_shortcode → NOT admin-only."""
        from hunter.pre_filter import (
            _all_nonce_creators_admin_only, _NONCE_ADMIN_ONLY,
        )
        _NONCE_ADMIN_ONLY.clear()
        root = self._make_plugin({
            "shortcode.php": """<?php
                add_shortcode('my_form', function() {
                    return wp_create_nonce('plugin_admin_nonce');
                });
            """,
        })
        self.assertFalse(_all_nonce_creators_admin_only(root, "plugin_admin_nonce"))

    def test_no_creators_returns_false(self):
        """No wp_create_nonce call → conservative False, let LLM decide."""
        from hunter.pre_filter import (
            _all_nonce_creators_admin_only, _NONCE_ADMIN_ONLY,
        )
        _NONCE_ADMIN_ONLY.clear()
        root = self._make_plugin({"empty.php": "<?php //"})
        self.assertFalse(_all_nonce_creators_admin_only(root, "ghost"))


class TestXssSourceCoercion(unittest.TestCase):
    def test_floatval_assignment_then_echo(self):
        from hunter.pre_filter import _xss_source_is_coerced
        lines = [
            "function f() {",
            "    $price = floatval($_POST['p']);",
            "    echo $price;",
            "}",
        ]
        # echo is on line 3 (1-indexed)
        self.assertTrue(_xss_source_is_coerced(lines, 3))

    def test_intval_with_cast(self):
        from hunter.pre_filter import _xss_source_is_coerced
        lines = [
            "$id = (int) $_GET['id'];",
            "echo $id;",
        ]
        self.assertTrue(_xss_source_is_coerced(lines, 2))

    def test_no_coercion_passes_through(self):
        from hunter.pre_filter import _xss_source_is_coerced
        lines = [
            "$msg = $_POST['msg'];",
            "echo $msg;",
        ]
        self.assertFalse(_xss_source_is_coerced(lines, 2))

    def test_unrelated_assignment_not_matched(self):
        """`$other = intval(...)` doesn't excuse `echo $tainted;`."""
        from hunter.pre_filter import _xss_source_is_coerced
        lines = [
            "$other = intval($_POST['o']);",
            "$msg = $_POST['msg'];",
            "echo $msg;",
        ]
        self.assertFalse(_xss_source_is_coerced(lines, 3))


class TestRestPermissionCallback(unittest.TestCase):
    """Resolve register_rest_route callback ↔ permission_callback pairs."""

    def _make_plugin(self, files):
        tmp = tempfile.mkdtemp(prefix="wphunter_test_")
        root = Path(tmp)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(textwrap.dedent(content), encoding="utf-8")
        return root

    def test_array_this_method_form(self):
        """The checkoutwc-lite form: array($this, 'method')."""
        from hunter.pre_filter import (
            _find_rest_permission_callback, _REST_PERM_CALLBACK,
        )
        _REST_PERM_CALLBACK.clear()
        root = self._make_plugin({
            "api.php": """<?php
                register_rest_route('ns/v1', 'setting/(?P<k>[\\S]+)', array(
                    'methods'             => WP_REST_Server::EDITABLE,
                    'callback'            => array( $this, 'update_setting' ),
                    'permission_callback' => array( $this, 'can_access_api' ),
                ));
            """,
        })
        self.assertEqual(
            _find_rest_permission_callback(root, "update_setting"),
            "can_access_api",
        )

    def test_bracket_this_method_form(self):
        """[$this, 'method'] short-array form."""
        from hunter.pre_filter import (
            _find_rest_permission_callback, _REST_PERM_CALLBACK,
        )
        _REST_PERM_CALLBACK.clear()
        root = self._make_plugin({
            "api.php": """<?php
                register_rest_route('ns/v1', 'thing', [
                    'methods'             => 'POST',
                    'callback'            => [$this, 'do_thing'],
                    'permission_callback' => [$this, 'allowed'],
                ]);
            """,
        })
        self.assertEqual(
            _find_rest_permission_callback(root, "do_thing"),
            "allowed",
        )

    def test_plain_function_name_form(self):
        """`'callback' => 'fn_name'` with a string-named permission_callback."""
        from hunter.pre_filter import (
            _find_rest_permission_callback, _REST_PERM_CALLBACK,
        )
        _REST_PERM_CALLBACK.clear()
        root = self._make_plugin({
            "api.php": """<?php
                register_rest_route('ns/v1', 'thing', [
                    'callback'            => 'my_handler',
                    'permission_callback' => 'check_my_perms',
                ]);
            """,
        })
        self.assertEqual(
            _find_rest_permission_callback(root, "my_handler"),
            "check_my_perms",
        )

    def test_class_method_form_returns_last_segment(self):
        """`'Cls::method'` collapses to just `method`."""
        from hunter.pre_filter import (
            _find_rest_permission_callback, _REST_PERM_CALLBACK,
        )
        _REST_PERM_CALLBACK.clear()
        root = self._make_plugin({
            "api.php": """<?php
                register_rest_route('ns/v1', 'thing', [
                    'callback'            => 'MyHandler::do',
                    'permission_callback' => 'Perms::ok',
                ]);
            """,
        })
        self.assertEqual(
            _find_rest_permission_callback(root, "do"),
            "ok",
        )

    def test_unregistered_callback_returns_none(self):
        from hunter.pre_filter import (
            _find_rest_permission_callback, _REST_PERM_CALLBACK,
        )
        _REST_PERM_CALLBACK.clear()
        root = self._make_plugin({"empty.php": "<?php // nothing"})
        self.assertIsNone(_find_rest_permission_callback(root, "ghost"))


class TestRevalidateCandidate(unittest.TestCase):
    """Stale-line revalidation guards the re-triage flow against drift."""

    def _make_plugin(self, files):
        tmp = tempfile.mkdtemp(prefix="wphunter_test_")
        root = Path(tmp)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return root

    def test_file_missing(self):
        from hunter.pre_filter import revalidate_candidate
        root = self._make_plugin({"a.php": "<?php // a"})
        self.assertEqual(
            revalidate_candidate(root, "gone.php", 1), "file_missing"
        )

    def test_line_out_of_range(self):
        from hunter.pre_filter import revalidate_candidate
        root = self._make_plugin({"a.php": "<?php\n// line 2\n"})
        self.assertEqual(
            revalidate_candidate(root, "a.php", 999), "line_out_of_range"
        )

    def test_valid_line_returns_none(self):
        from hunter.pre_filter import revalidate_candidate
        root = self._make_plugin({"a.php": "<?php\n$x = 1;\n$y = 2;\n"})
        self.assertIsNone(revalidate_candidate(root, "a.php", 2))


# ---------------------------------------------------------------------------
# Verifier rejection regex: critical for not turning FPs into "confirmed"
# ---------------------------------------------------------------------------

class TestVerifierRejections(unittest.TestCase):
    def setUp(self):
        from hunter.verifier import _detect_rejection
        self.detect = _detect_rejection

    def test_minus_one_body(self):
        self.assertEqual(self.detect("-1"), "wp_auth_rejected")
        self.assertEqual(self.detect("-1\n"), "wp_auth_rejected")
        self.assertEqual(self.detect("  -1  "), "wp_auth_rejected")

    def test_zero_body(self):
        self.assertEqual(self.detect("0"), "wp_auth_rejected")
        self.assertEqual(self.detect("\n0\n"), "wp_auth_rejected")

    def test_permission_messages(self):
        self.assertEqual(
            self.detect("You do not have sufficient permissions"),
            "wp_auth_rejected",
        )
        self.assertEqual(
            self.detect("Are you sure you want to do this?"),
            "wp_auth_rejected",
        )
        self.assertEqual(
            self.detect("Sorry, you are not allowed to access this page"),
            "wp_auth_rejected",
        )

    def test_json_error_with_negative_code(self):
        body = '{"success":false,"data":"-1"}'
        self.assertEqual(self.detect(body), "wp_auth_rejected")

    def test_real_content_not_rejected(self):
        # These MUST return None — false positives here would turn real
        # findings into "failed".
        self.assertIsNone(self.detect('{"success":true,"data":{"id":42}}'))
        self.assertIsNone(self.detect("<html><body>Hello -1 world</body></html>"))
        # "Are you sure" without the full phrase
        self.assertIsNone(self.detect("Are you sure about that?"))

    def test_critical_error_pattern(self):
        from hunter.verifier import _WP_CRITICAL_RE
        self.assertTrue(_WP_CRITICAL_RE.search(
            "There has been a critical error on this website."
        ))
        self.assertTrue(_WP_CRITICAL_RE.search(
            "There has been a critical error on this site."
        ))
        self.assertIsNone(_WP_CRITICAL_RE.search("Everything is fine."))


# ---------------------------------------------------------------------------
# Run context manager: counters write to the runs table
# ---------------------------------------------------------------------------

class TestRunsTracker(unittest.TestCase):
    def setUp(self):
        # Each test gets its own DB
        self.fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(self.fd)
        os.environ["HUNTER_DB_PATH"] = self.path
        from hunter.db import migrate
        migrate()

    def tearDown(self):
        for ext in ("", "-wal", "-shm"):
            try:
                os.unlink(self.path + ext)
            except OSError:
                pass
        del os.environ["HUNTER_DB_PATH"]

    def test_bump_records_counter(self):
        from hunter.runs import Run, funnel_totals
        with Run("scan", plugin_slug="x") as r:
            r.bump("raw_findings", 7)
            r.bump("inserted_candidates", 5)
        t = funnel_totals()
        self.assertEqual(t["raw_findings"], 7)
        self.assertEqual(t["inserted_candidates"], 5)

    def test_invalid_counter_silently_dropped(self):
        """Typos in counter names must not crash the pipeline."""
        from hunter.runs import Run, funnel_totals
        with Run("scan") as r:
            r.bump("not_a_real_counter", 9999)
            r.bump("raw_findings", 3)
        t = funnel_totals()
        self.assertEqual(t["raw_findings"], 3)

    def test_filter_by_plugin(self):
        from hunter.runs import Run, funnel_totals
        with Run("scan", plugin_slug="a") as r:
            r.bump("raw_findings", 10)
        with Run("scan", plugin_slug="b") as r:
            r.bump("raw_findings", 20)
        self.assertEqual(funnel_totals("a")["raw_findings"], 10)
        self.assertEqual(funnel_totals("b")["raw_findings"], 20)
        self.assertEqual(funnel_totals()["raw_findings"], 30)


if __name__ == "__main__":
    unittest.main()
