<?php
/**
 * Plugin Name: Private File Uploader
 * Description: Secure file uploads to a per-user directory via custom REST endpoints. Pairs with a React Native client.
 * Version: 0.1.0
 * Author: Danilo Ercoli
 * License: MIT
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

require_once __DIR__ . '/src/Plugin.php';

add_action( 'plugins_loaded', function () {
    \PFU\Plugin::init();
} );
