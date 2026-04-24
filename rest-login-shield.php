<?php
/**
 * Plugin Name:       REST & Login Shield
 * Plugin URI:        https://github.com/weblixpl/rest-login-shield
 * Description:       Minimal security hardening: blocks REST API user enumeration, hides server metadata, and protects wp-login.php against brute force attacks.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            weblixpl
 * Author URI:        https://github.com/weblixpl
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       rest-login-shield
 * Domain Path:       /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

define('RLS_VERSION', '1.0.0');
define('RLS_FILE', __FILE__);
define('RLS_PATH', plugin_dir_path(__FILE__));
define('RLS_URL', plugin_dir_url(__FILE__));
define('RLS_BASENAME', plugin_basename(__FILE__));

require_once RLS_PATH . 'includes/class-ip-helper.php';
require_once RLS_PATH . 'includes/class-activator.php';
require_once RLS_PATH . 'includes/class-rest-api-guard.php';
require_once RLS_PATH . 'includes/class-author-guard.php';
require_once RLS_PATH . 'includes/class-brute-force.php';
require_once RLS_PATH . 'includes/class-settings.php';
require_once RLS_PATH . 'includes/class-plugin.php';

register_activation_hook(__FILE__, ['RLS_Activator', 'activate']);

add_action('plugins_loaded', ['RLS_Plugin', 'init']);

// GitHub auto-update via plugin-update-checker
if (file_exists(RLS_PATH . 'vendor/plugin-update-checker/plugin-update-checker.php')) {
    require_once RLS_PATH . 'vendor/plugin-update-checker/plugin-update-checker.php';
    $rls_updater = YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
        'https://github.com/weblixpl/rest-login-shield/',
        __FILE__,
        'rest-login-shield'
    );
    $rls_updater->getVcsApi()->enableReleaseAssets();
}
