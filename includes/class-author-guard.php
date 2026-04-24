<?php
if (!defined('ABSPATH')) {
    exit;
}

class RLS_Author_Guard
{
    public function __construct()
    {
        add_action('template_redirect', [$this, 'block_author_enum']);
    }

    public function block_author_enum()
    {
        if (is_admin() || is_user_logged_in()) {
            return;
        }
        if (isset($_GET['author'])) {
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }
}
