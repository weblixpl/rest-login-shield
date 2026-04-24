<?php
if (!defined('ABSPATH')) {
    exit;
}

class RLS_Activator
{
    public static function activate()
    {
        global $wpdb;
        $table   = $wpdb->prefix . 'rls_login_log';
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(45) NOT NULL,
            username VARCHAR(60) DEFAULT '',
            attempted_at DATETIME NOT NULL,
            blocked TINYINT(1) NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            KEY idx_ip (ip),
            KEY idx_attempted_at (attempted_at)
        ) {$charset};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);

        if (get_option(RLS_Plugin::OPTION_KEY) === false) {
            add_option(RLS_Plugin::OPTION_KEY, RLS_Plugin::get_defaults());
        }
    }
}
