<?php

/**
 * Plugin Name: Private File Uploader
 * Description: Secure file uploads to a per-user directory via custom REST endpoints. Pairs with a React Native client.
 * Version: 0.1.0
 * Author: Danilo Ercoli
 * License: MIT
 */

if (!defined('ABSPATH')) {
    exit;
}

define('PFU_PLUGIN_FILE', __FILE__);
define('PFU_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('PFU_PLUGIN_URL', plugin_dir_url(__FILE__));
define('PFU_VERSION', '0.1.0');

// Load classes
require_once __DIR__ . '/src/Utils.php';
require_once __DIR__ . '/src/Plugin.php';
require_once __DIR__ . '/src/Admin.php';

add_action('plugins_loaded', function () {
    \PFU\Plugin::init();
    \PFU\Admin::init();

    \PFU\Utils::log_info('Plugin initialized', [
        'version' => PFU_VERSION,
        'php_version' => PHP_VERSION,
        'wp_version' => get_bloginfo('version')
    ]);
});

add_filter('plugin_action_links_' . plugin_basename(__FILE__), function (array $links) {
    $url = admin_url('admin.php?page=pfu-safe-deactivate');
    array_unshift($links, '<a href="' . esc_url($url) . '">' . esc_html__('Safe Deactivate', 'pfu') . '</a>');
    return $links;
});

// Log plugin activation
register_activation_hook(__FILE__, function () {
    \PFU\Utils::log_info('Plugin activated');
});

// Log plugin deactivation
register_deactivation_hook(__FILE__, function () {
    \PFU\Utils::log_info('Plugin deactivated');
});
