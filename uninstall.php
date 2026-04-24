<?php
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

$table = $wpdb->prefix . 'rls_login_log';
$wpdb->query("DROP TABLE IF EXISTS {$table}");

delete_option('rls_settings');

$like = $wpdb->esc_like('_transient_rls_bf_') . '%';
$wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like));
$like = $wpdb->esc_like('_transient_timeout_rls_bf_') . '%';
$wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like));
