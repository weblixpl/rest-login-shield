<?php
if (!defined('ABSPATH')) {
    exit;
}

class RLS_Author_Guard
{
    public function __construct()
    {
        add_action('template_redirect', [$this, 'block_author_enum'], 1);
        add_filter('redirect_canonical', [$this, 'block_canonical_author_redirect'], 10, 2);
        add_filter('the_author', [$this, 'mask_feed_author']);
        add_filter('the_author_posts_link', [$this, 'mask_author_posts_link']);
    }

    public function block_author_enum()
    {
        if (is_admin() || is_user_logged_in()) {
            return;
        }
        if (isset($_GET['author']) || is_author()) {
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }

    public function block_canonical_author_redirect($redirect_url, $requested_url)
    {
        if (is_user_logged_in()) {
            return $redirect_url;
        }
        if (isset($_GET['author']) || (is_string($redirect_url) && strpos($redirect_url, '/author/') !== false)) {
            return home_url('/');
        }
        return $redirect_url;
    }

    public function mask_feed_author($display_name)
    {
        if (is_feed()) {
            return get_bloginfo('name');
        }
        return $display_name;
    }

    public function mask_author_posts_link($link)
    {
        if (is_feed()) {
            return get_bloginfo('name');
        }
        return $link;
    }
}
