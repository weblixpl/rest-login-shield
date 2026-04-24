<?php
if (!defined('ABSPATH')) {
    exit;
}

class RLS_Plugin
{
    const OPTION_KEY = 'rls_settings';

    public static function init()
    {
        load_plugin_textdomain('rest-login-shield', false, dirname(RLS_BASENAME) . '/languages');

        $settings = self::get_settings();

        if (!empty($settings['protect_rest_users']) || !empty($settings['protect_rest_metadata'])) {
            new RLS_Rest_Api_Guard($settings);
        }
        if (!empty($settings['protect_author_enum'])) {
            new RLS_Author_Guard();
        }
        if (!empty($settings['protect_brute_force'])) {
            new RLS_Brute_Force($settings);
        }
        if (!empty($settings['disable_comments'])) {
            new RLS_Comments_Guard();
        }
        if (is_admin()) {
            new RLS_Settings();
        }
    }

    public static function get_settings()
    {
        $defaults = self::get_defaults();
        $saved    = get_option(self::OPTION_KEY, []);
        if (!is_array($saved)) {
            $saved = [];
        }
        return array_merge($defaults, $saved);
    }

    public static function get_defaults()
    {
        return [
            'protect_rest_users'    => 1,
            'protect_rest_metadata' => 1,
            'protect_author_enum'   => 1,
            'protect_brute_force'   => 1,
            'max_attempts'          => 5,
            'lockout_minutes'       => 30,
            'ip_whitelist'          => '',
            'trusted_proxy'         => 'none',
            'disable_comments'      => 0,
        ];
    }
}
