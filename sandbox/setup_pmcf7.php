<?php
// Create a CF7 form with a text field mapped to post_content.
$form_id = wp_insert_post([
    'post_type'    => 'wpcf7_contact_form',
    'post_status'  => 'publish',
    'post_title'   => 'Attack Form',
    'post_name'    => 'attack-form',
]);

// CF7 internals: form template, mail, messages, additional settings.
update_post_meta( $form_id, '_form', '[text your-message] [submit "Send"]' );
update_post_meta( $form_id, '_mail', [
    'subject'      => 'Test',
    'sender'       => 'admin@test.com',
    'body'         => '[your-message]',
    'recipient'    => 'admin@test.com',
    'mailHeader'   => '',
    'use_html'     => 0,
    'excludeBlank' => 0,
    'attachments'  => '',
] );
update_post_meta( $form_id, '_mail_2', [
    'active'       => false,
    'subject'      => '',
    'sender'       => '',
    'body'         => '',
    'recipient'    => '',
    'mailHeader'   => '',
    'use_html'     => 0,
    'excludeBlank' => 0,
    'attachments'  => '',
] );
update_post_meta( $form_id, '_messages',            [] );
update_post_meta( $form_id, '_additional_settings', '' );

// c2p mapping meta.
// _cf7_2_post-map = 'publish' makes is_live() return true.
// _cf7_2_post-type = 'post'   is the target post type.
// _cf7_2_post-taxonomy = []   required by load_post_mapping (iterates over it).
// cf7_2_post_map-editor = 'your-message'  maps CF7 field -> post_content.
// (key = 'cf7_2_post_map-{post_field}', value = '{cf7_field_name}')
update_post_meta( $form_id, '_cf7_2_post-map',      'publish' );
update_post_meta( $form_id, '_cf7_2_post-type',     'post' );
update_post_meta( $form_id, '_cf7_2_post-taxonomy', [] );
update_post_meta( $form_id, 'cf7_2_post_map-editor', 'your-message' );

// Create a victim post that the attacker will overwrite.
$victim_id = wp_insert_post([
    'post_type'    => 'post',
    'post_status'  => 'publish',
    'post_title'   => 'Victim Post - Original',
    'post_content' => 'This is the original content. It should not be changed.',
]);

echo "CF7 form ID: $form_id\n";
echo "Victim post ID: $victim_id\n";
echo "CF7 version: " . WPCF7_VERSION . "\n";
