<?php
if (!defined('ABSPATH')) {
    exit;
}

class RLS_Login_Honeypot
{
    const FIELD_NAME = 'website';

    private $settings;

    public function __construct(array $settings)
    {
        $this->settings = $settings;
        add_action('login_form', [$this, 'inject_field']);
        add_action('register_form', [$this, 'inject_field']);
        add_action('lostpassword_form', [$this, 'inject_field']);
        add_filter('authenticate', [$this, 'check_login'], 1, 3);
        add_action('lostpassword_post', [$this, 'check_lostpassword']);
        add_filter('registration_errors', [$this, 'check_registration'], 10, 1);
    }

    public function inject_field()
    {
        $label = esc_html__('Website (leave blank)', 'rest-login-shield');
        $name  = esc_attr(self::FIELD_NAME);
        echo '<div style="position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;" aria-hidden="true">';
        echo '<label for="rls_hp_field">' . $label . '</label>';
        echo '<input type="text" name="' . $name . '" id="rls_hp_field" tabindex="-1" autocomplete="off" value="">';
        echo '</div>';
    }

    public function check_login($user, $username, $password)
    {
        if (empty($username) && empty($password)) {
            return $user;
        }
        if (!$this->is_triggered()) {
            return $user;
        }
        $this->handle_trigger((string) $username);
        return new WP_Error(
            'invalid_credentials',
            __('Authentication failed.', 'rest-login-shield')
        );
    }

    public function check_lostpassword()
    {
        if (!$this->is_triggered()) {
            return;
        }
        $login = isset($_POST['user_login']) ? sanitize_text_field(wp_unslash($_POST['user_login'])) : '';
        $this->handle_trigger($login);
        wp_die(esc_html__('Authentication failed.', 'rest-login-shield'), 403);
    }

    public function check_registration($errors)
    {
        if ($this->is_triggered()) {
            $login = isset($_POST['user_login']) ? sanitize_text_field(wp_unslash($_POST['user_login'])) : '';
            $this->handle_trigger($login);
            if (is_wp_error($errors)) {
                $errors->add('rls_honeypot', __('Authentication failed.', 'rest-login-shield'));
            }
        }
        return $errors;
    }

    private function is_triggered()
    {
        if (!isset($_POST[self::FIELD_NAME])) {
            return false;
        }
        $value = wp_unslash($_POST[self::FIELD_NAME]);
        return is_string($value) && $value !== '';
    }

    private function handle_trigger($username)
    {
        $ip = RLS_IP_Helper::get_client_ip($this->settings['trusted_proxy'] ?? 'none');
        if (!$ip) {
            return;
        }
        if (RLS_IP_Helper::is_whitelisted($ip, (string) ($this->settings['ip_whitelist'] ?? ''))) {
            return;
        }
        RLS_Brute_Force::record_honeypot_hit($ip, $username, $this->settings);
        $GLOBALS['rls_honeypot_handled'] = true;
    }
}
