<?php
if (!defined('ABSPATH')) {
    exit;
}

class RLS_Rest_Api_Guard
{
    private $settings;

    public function __construct(array $settings)
    {
        $this->settings = $settings;

        if (!empty($settings['protect_rest_users'])) {
            add_filter('rest_endpoints', [$this, 'hide_users_endpoints']);
        }
        if (!empty($settings['protect_rest_metadata'])) {
            add_filter('rest_index', [$this, 'strip_metadata']);
        }
    }

    public function hide_users_endpoints($endpoints)
    {
        if (is_user_logged_in()) {
            return $endpoints;
        }
        unset($endpoints['/wp/v2/users']);
        unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        return $endpoints;
    }

    public function strip_metadata($response)
    {
        if (is_user_logged_in()) {
            return $response;
        }
        $data = $response->get_data();
        unset($data['description']);
        unset($data['gmt_offset']);
        unset($data['timezone_string']);
        $response->set_data($data);
        return $response;
    }
}
