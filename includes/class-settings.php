<?php
if (!defined('ABSPATH')) {
    exit;
}

class RLS_Settings
{
    const MENU_SLUG  = 'rest-login-shield';
    const NONCE_NAME = 'rls_settings_nonce';

    public function __construct()
    {
        add_action('admin_menu', [$this, 'add_menu']);
        add_action('admin_init', [$this, 'handle_post']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_filter('plugin_action_links_' . RLS_BASENAME, [$this, 'action_links']);
    }

    public function add_menu()
    {
        add_options_page(
            __('REST & Login Shield', 'rest-login-shield'),
            __('REST & Login Shield', 'rest-login-shield'),
            'manage_options',
            self::MENU_SLUG,
            [$this, 'render_page']
        );
    }

    public function action_links($links)
    {
        $url  = admin_url('options-general.php?page=' . self::MENU_SLUG);
        $link = '<a href="' . esc_url($url) . '">' . esc_html__('Settings', 'rest-login-shield') . '</a>';
        array_unshift($links, $link);
        return $links;
    }

    public function enqueue_assets($hook)
    {
        if ($hook !== 'settings_page_' . self::MENU_SLUG) {
            return;
        }
        wp_enqueue_style('rls-admin', RLS_URL . 'assets/css/admin.css', [], RLS_VERSION);
    }

    public function handle_post()
    {
        if (!isset($_POST['rls_action'])) {
            return;
        }
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to perform this action.', 'rest-login-shield'));
        }
        check_admin_referer('rls_settings_save', self::NONCE_NAME);

        $action = sanitize_key($_POST['rls_action']);

        if ($action === 'save_settings') {
            $this->save_settings();
        } elseif ($action === 'unblock_ip') {
            $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
            if ($ip && RLS_Brute_Force::unblock_ip($ip)) {
                add_settings_error('rls', 'rls_unblocked', sprintf(
                    /* translators: %s: IP address */
                    __('IP %s has been unblocked.', 'rest-login-shield'),
                    $ip
                ), 'updated');
            }
        }

        set_transient('settings_errors', get_settings_errors(), 30);
        wp_safe_redirect(add_query_arg(['page' => self::MENU_SLUG, 'settings-updated' => '1'], admin_url('options-general.php')));
        exit;
    }

    private function save_settings()
    {
        $defaults = RLS_Plugin::get_defaults();
        $raw      = isset($_POST['rls_settings']) && is_array($_POST['rls_settings']) ? wp_unslash($_POST['rls_settings']) : [];

        $new = [
            'protect_rest_users'    => !empty($raw['protect_rest_users']) ? 1 : 0,
            'protect_rest_metadata' => !empty($raw['protect_rest_metadata']) ? 1 : 0,
            'protect_author_enum'   => !empty($raw['protect_author_enum']) ? 1 : 0,
            'protect_brute_force'   => !empty($raw['protect_brute_force']) ? 1 : 0,
            'max_attempts'          => isset($raw['max_attempts']) ? max(1, min(50, (int) $raw['max_attempts'])) : $defaults['max_attempts'],
            'lockout_minutes'       => isset($raw['lockout_minutes']) ? max(1, min(1440, (int) $raw['lockout_minutes'])) : $defaults['lockout_minutes'],
            'ip_whitelist'          => isset($raw['ip_whitelist']) ? $this->sanitize_whitelist($raw['ip_whitelist']) : '',
        ];

        update_option(RLS_Plugin::OPTION_KEY, $new);
        add_settings_error('rls', 'rls_saved', __('Settings saved.', 'rest-login-shield'), 'updated');
    }

    private function sanitize_whitelist($raw)
    {
        $lines  = preg_split('/\r\n|\r|\n/', (string) $raw);
        $clean  = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            if (strpos($line, '#') === 0) {
                $clean[] = $line;
                continue;
            }
            if (strpos($line, '/') !== false) {
                list($subnet, $mask) = array_pad(explode('/', $line, 2), 2, null);
                if (filter_var($subnet, FILTER_VALIDATE_IP) && is_numeric($mask)) {
                    $clean[] = $line;
                }
            } elseif (filter_var($line, FILTER_VALIDATE_IP)) {
                $clean[] = $line;
            }
        }
        return implode("\n", $clean);
    }

    public function render_page()
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $settings     = RLS_Plugin::get_settings();
        $blocked_ips  = RLS_Brute_Force::get_blocked_ips((int) $settings['max_attempts']);
        $log          = RLS_Brute_Force::get_recent_log(50);
        $current_ip   = RLS_IP_Helper::get_client_ip();
        ?>
        <div class="wrap rls-wrap">
            <h1><?php esc_html_e('REST & Login Shield', 'rest-login-shield'); ?></h1>

            <?php settings_errors('rls'); ?>

            <p class="description">
                <?php
                printf(
                    /* translators: %s: current visitor IP */
                    esc_html__('Your current IP: %s', 'rest-login-shield'),
                    '<code>' . esc_html($current_ip) . '</code>'
                );
                ?>
            </p>

            <form method="post" action="">
                <?php wp_nonce_field('rls_settings_save', self::NONCE_NAME); ?>
                <input type="hidden" name="rls_action" value="save_settings">

                <h2><?php esc_html_e('Protections', 'rest-login-shield'); ?></h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php esc_html_e('REST API user enumeration', 'rest-login-shield'); ?></th>
                        <td>
                            <label><input type="checkbox" name="rls_settings[protect_rest_users]" value="1" <?php checked($settings['protect_rest_users'], 1); ?>>
                                <?php esc_html_e('Hide /wp-json/wp/v2/users for unauthenticated requests', 'rest-login-shield'); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('REST API metadata', 'rest-login-shield'); ?></th>
                        <td>
                            <label><input type="checkbox" name="rls_settings[protect_rest_metadata]" value="1" <?php checked($settings['protect_rest_metadata'], 1); ?>>
                                <?php esc_html_e('Strip description, gmt_offset, timezone_string from /wp-json/', 'rest-login-shield'); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Author enumeration', 'rest-login-shield'); ?></th>
                        <td>
                            <label><input type="checkbox" name="rls_settings[protect_author_enum]" value="1" <?php checked($settings['protect_author_enum'], 1); ?>>
                                <?php esc_html_e('Redirect ?author=N requests to the home page', 'rest-login-shield'); ?></label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Brute force protection', 'rest-login-shield'); ?></th>
                        <td>
                            <label><input type="checkbox" name="rls_settings[protect_brute_force]" value="1" <?php checked($settings['protect_brute_force'], 1); ?>>
                                <?php esc_html_e('Lock out IPs after too many failed login attempts', 'rest-login-shield'); ?></label>
                        </td>
                    </tr>
                </table>

                <h2><?php esc_html_e('Brute force settings', 'rest-login-shield'); ?></h2>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="rls_max_attempts"><?php esc_html_e('Max failed attempts', 'rest-login-shield'); ?></label></th>
                        <td>
                            <input type="number" id="rls_max_attempts" name="rls_settings[max_attempts]" value="<?php echo esc_attr($settings['max_attempts']); ?>" min="1" max="50" class="small-text">
                            <p class="description"><?php esc_html_e('Number of failed login attempts allowed before lockout.', 'rest-login-shield'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="rls_lockout_minutes"><?php esc_html_e('Lockout duration (minutes)', 'rest-login-shield'); ?></label></th>
                        <td>
                            <input type="number" id="rls_lockout_minutes" name="rls_settings[lockout_minutes]" value="<?php echo esc_attr($settings['lockout_minutes']); ?>" min="1" max="1440" class="small-text">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="rls_ip_whitelist"><?php esc_html_e('IP whitelist', 'rest-login-shield'); ?></label></th>
                        <td>
                            <textarea id="rls_ip_whitelist" name="rls_settings[ip_whitelist]" rows="5" cols="40" class="large-text code"><?php echo esc_textarea($settings['ip_whitelist']); ?></textarea>
                            <p class="description"><?php esc_html_e('One entry per line. Supports single IPv4/IPv6 or CIDR (e.g. 192.168.1.0/24). Lines starting with # are comments.', 'rest-login-shield'); ?></p>
                        </td>
                    </tr>
                </table>

                <?php submit_button(__('Save settings', 'rest-login-shield')); ?>
            </form>

            <hr>

            <h2><?php esc_html_e('Currently blocked IPs', 'rest-login-shield'); ?></h2>
            <?php if (empty($blocked_ips)) : ?>
                <p><?php esc_html_e('No IPs are currently blocked.', 'rest-login-shield'); ?></p>
            <?php else : ?>
                <table class="widefat striped">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('IP address', 'rest-login-shield'); ?></th>
                            <th><?php esc_html_e('Failed attempts', 'rest-login-shield'); ?></th>
                            <th><?php esc_html_e('Last attempt', 'rest-login-shield'); ?></th>
                            <th><?php esc_html_e('Action', 'rest-login-shield'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($blocked_ips as $row) : ?>
                            <tr>
                                <td><code><?php echo esc_html($row['ip']); ?></code></td>
                                <td><?php echo esc_html($row['attempts']); ?></td>
                                <td><?php echo esc_html($row['last_seen']); ?></td>
                                <td>
                                    <form method="post" style="display:inline;">
                                        <?php wp_nonce_field('rls_settings_save', self::NONCE_NAME); ?>
                                        <input type="hidden" name="rls_action" value="unblock_ip">
                                        <input type="hidden" name="ip" value="<?php echo esc_attr($row['ip']); ?>">
                                        <button type="submit" class="button button-small"><?php esc_html_e('Unblock', 'rest-login-shield'); ?></button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <hr>

            <h2><?php esc_html_e('Recent failed login attempts', 'rest-login-shield'); ?></h2>
            <?php if (empty($log)) : ?>
                <p><?php esc_html_e('No failed login attempts recorded yet.', 'rest-login-shield'); ?></p>
            <?php else : ?>
                <table class="widefat striped">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Date', 'rest-login-shield'); ?></th>
                            <th><?php esc_html_e('IP address', 'rest-login-shield'); ?></th>
                            <th><?php esc_html_e('Username tried', 'rest-login-shield'); ?></th>
                            <th><?php esc_html_e('Blocked', 'rest-login-shield'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($log as $row) : ?>
                            <tr>
                                <td><?php echo esc_html($row->attempted_at); ?></td>
                                <td><code><?php echo esc_html($row->ip); ?></code></td>
                                <td><?php echo esc_html($row->username); ?></td>
                                <td><?php echo $row->blocked ? '<span class="rls-badge rls-badge-blocked">' . esc_html__('Yes', 'rest-login-shield') . '</span>' : esc_html__('No', 'rest-login-shield'); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        <?php
    }
}
