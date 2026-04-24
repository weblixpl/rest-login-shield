<?php
if (!defined('ABSPATH')) {
    exit;
}

class RLS_Comments_Guard
{
    public function __construct()
    {
        add_filter('comments_open', '__return_false', 99);
        add_filter('pings_open', '__return_false', 99);
        add_filter('comments_array', '__return_empty_array', 99);
        add_filter('rest_endpoints', [$this, 'remove_rest_endpoints']);
        add_filter('xmlrpc_methods', [$this, 'remove_xmlrpc_methods']);

        add_action('init', [$this, 'block_front_controller'], 1);

        if (is_admin()) {
            add_action('admin_menu', [$this, 'remove_admin_menu']);
            add_action('wp_dashboard_setup', [$this, 'remove_dashboard_widget']);
            add_action('admin_init', [$this, 'redirect_comments_admin_page']);
        }

        add_action('wp_before_admin_bar_render', [$this, 'remove_admin_bar_comments']);
        add_action('template_redirect', [$this, 'remove_feed_links']);
    }

    public function block_front_controller()
    {
        if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $script = isset($_SERVER['SCRIPT_NAME']) ? basename($_SERVER['SCRIPT_NAME']) : '';
            if ($script === 'wp-comments-post.php') {
                status_header(403);
                nocache_headers();
                exit;
            }
        }
    }

    public function remove_rest_endpoints($endpoints)
    {
        foreach (array_keys($endpoints) as $route) {
            if (strpos($route, '/wp/v2/comments') === 0) {
                unset($endpoints[$route]);
            }
        }
        return $endpoints;
    }

    public function remove_xmlrpc_methods($methods)
    {
        unset(
            $methods['wp.newComment'],
            $methods['wp.getComment'],
            $methods['wp.getComments'],
            $methods['wp.getCommentCount'],
            $methods['wp.editComment'],
            $methods['wp.deleteComment'],
            $methods['wp.getCommentStatusList'],
            $methods['pingback.ping'],
            $methods['pingback.extensions.getPingbacks']
        );
        return $methods;
    }

    public function remove_admin_menu()
    {
        remove_menu_page('edit-comments.php');
    }

    public function remove_dashboard_widget()
    {
        remove_meta_box('dashboard_recent_comments', 'dashboard', 'normal');
    }

    public function redirect_comments_admin_page()
    {
        global $pagenow;
        if ($pagenow === 'edit-comments.php' || $pagenow === 'comment.php' || $pagenow === 'options-discussion.php') {
            wp_safe_redirect(admin_url(), 302, 'REST & Login Shield');
            exit;
        }
    }

    public function remove_admin_bar_comments()
    {
        global $wp_admin_bar;
        if ($wp_admin_bar instanceof WP_Admin_Bar) {
            $wp_admin_bar->remove_node('comments');
        }
    }

    public function remove_feed_links()
    {
        add_filter('feed_links_show_comments_feed', '__return_false');
    }
}
