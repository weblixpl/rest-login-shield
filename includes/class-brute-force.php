<?php
if (!defined('ABSPATH')) {
    exit;
}

class RLS_Brute_Force
{
    const TRANSIENT_PREFIX = 'rls_bf_';

    private $settings;
    private $max_attempts;
    private $lockout_seconds;

    public function __construct(array $settings)
    {
        $this->settings        = $settings;
        $this->max_attempts    = max(1, (int) ($settings['max_attempts'] ?? 5));
        $this->lockout_seconds = max(60, (int) ($settings['lockout_minutes'] ?? 30) * 60);

        add_filter('authenticate', [$this, 'check_lockout'], 30, 3);
        add_action('wp_login_failed', [$this, 'on_failure']);
        add_action('wp_login', [$this, 'on_success']);
    }

    public function check_lockout($user, $username, $password)
    {
        if (empty($username) && empty($password)) {
            return $user;
        }
        $ip = RLS_IP_Helper::get_client_ip();
        if (!$ip || $this->is_whitelisted($ip)) {
            return $user;
        }
        $attempts = (int) get_transient(self::TRANSIENT_PREFIX . md5($ip));
        if ($attempts >= $this->max_attempts) {
            $remaining = (int) ceil($this->lockout_seconds / 60);
            return new WP_Error(
                'rls_too_many_attempts',
                sprintf(
                    /* translators: %d: number of minutes until lockout expires */
                    __('Too many failed login attempts. Try again in %d minutes.', 'rest-login-shield'),
                    $remaining
                )
            );
        }
        return $user;
    }

    public function on_failure($username)
    {
        $ip = RLS_IP_Helper::get_client_ip();
        if (!$ip || $this->is_whitelisted($ip)) {
            return;
        }
        $key      = self::TRANSIENT_PREFIX . md5($ip);
        $attempts = (int) get_transient($key);
        $attempts++;
        set_transient($key, $attempts, $this->lockout_seconds);
        $this->log_attempt($ip, (string) $username, $attempts >= $this->max_attempts);
    }

    public function on_success($username)
    {
        $ip = RLS_IP_Helper::get_client_ip();
        if (!$ip) {
            return;
        }
        delete_transient(self::TRANSIENT_PREFIX . md5($ip));
    }

    private function is_whitelisted($ip)
    {
        return RLS_IP_Helper::is_whitelisted($ip, (string) ($this->settings['ip_whitelist'] ?? ''));
    }

    private function log_attempt($ip, $username, $blocked)
    {
        global $wpdb;
        $table = $wpdb->prefix . 'rls_login_log';
        $wpdb->insert(
            $table,
            [
                'ip'           => $ip,
                'username'     => mb_substr($username, 0, 60),
                'attempted_at' => current_time('mysql'),
                'blocked'      => $blocked ? 1 : 0,
            ],
            ['%s', '%s', '%s', '%d']
        );
        $this->prune_old_logs();
    }

    private function prune_old_logs()
    {
        global $wpdb;
        $table = $wpdb->prefix . 'rls_login_log';
        $wpdb->query(
            "DELETE FROM {$table} WHERE id NOT IN (SELECT id FROM (SELECT id FROM {$table} ORDER BY id DESC LIMIT 200) tmp)"
        );
    }

    public static function unblock_ip($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        return delete_transient(self::TRANSIENT_PREFIX . md5($ip));
    }

    public static function get_blocked_ips($max_attempts)
    {
        global $wpdb;
        $table = $wpdb->prefix . 'rls_login_log';
        $rows = $wpdb->get_results(
            "SELECT ip, MAX(attempted_at) AS last_seen FROM {$table} WHERE blocked = 1 GROUP BY ip ORDER BY last_seen DESC LIMIT 100"
        );
        $result = [];
        foreach ($rows as $row) {
            $attempts = (int) get_transient(self::TRANSIENT_PREFIX . md5($row->ip));
            if ($attempts >= $max_attempts) {
                $result[] = [
                    'ip'        => $row->ip,
                    'attempts'  => $attempts,
                    'last_seen' => $row->last_seen,
                ];
            }
        }
        return $result;
    }

    public static function get_recent_log($limit = 50)
    {
        global $wpdb;
        $table = $wpdb->prefix . 'rls_login_log';
        $limit = max(1, min(200, (int) $limit));
        return $wpdb->get_results(
            $wpdb->prepare("SELECT ip, username, attempted_at, blocked FROM {$table} ORDER BY id DESC LIMIT %d", $limit)
        );
    }
}
