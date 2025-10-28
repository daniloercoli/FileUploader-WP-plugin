<?php

namespace PFU;

if (!defined('ABSPATH')) {
    exit;
}

class Admin
{
    const OPTION_KEY = 'pfu_settings';

    /**
     * Initialize admin hooks
     */
    public static function init(): void
    {
        add_action('admin_menu', [__CLASS__, 'register_menu']);
        add_action('admin_init', [__CLASS__, 'register_settings']);
        add_action('admin_post_pfu_delete_file', [__CLASS__, 'handle_delete_file']);
        add_action('admin_post_pfu_safe_deactivate_handle', [__CLASS__, 'handle_safe_deactivate']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'enqueue_admin_styles']);

        // User deletion hooks (single site)
        add_action('load-users.php', [__CLASS__, 'maybe_hook_users_notice']);
        add_action('delete_user_form', [__CLASS__, 'delete_user_form'], 10, 1);
        add_action('delete_user', [__CLASS__, 'handle_delete_user'], 10, 1);

        // Multisite user deletion
        add_action('wpmu_delete_user', [__CLASS__, 'handle_delete_user'], 10, 1);
    }

    /**
     * Enqueue admin styles
     */
    public static function enqueue_admin_styles(string $hook): void
    {
        // Only load on our plugin pages
        if (strpos($hook, 'pfu-') === false && strpos($hook, 'private-uploader') === false) {
            return;
        }

        wp_add_inline_style('wp-admin', self::get_admin_css());
    }

    /**
     * Get admin CSS
     *
     * @return string CSS content
     */
    private static function get_admin_css(): string
    {
        return '
            .pfu-cards { display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }
            .pfu-card { background: #fff; border: 1px solid #e3e3e3; border-radius: 8px; padding: 16px; min-width: 260px; }
            .pfu-card h2 { margin: 0 0 8px; font-size: 16px; }
            .pfu-list { margin: 8px 0 0 18px; }
            .pfu-muted { color: #666; }
            .pfu-actions { margin-top: 16px; }
            .pfu-server-limits { margin-top: 16px; background: #fff; border: 1px solid #e3e3e3; border-radius: 8px; padding: 16px; }
            .pfu-warning-box { margin-top: 8px; padding: 8px 12px; border-left: 4px solid #d63638; background: #fff3f3; }
            .column-pfu-preview { width: 60px; }
            .pfu-thumb { width: 48px; height: 48px; object-fit: cover; border-radius: 4px; background: #f3f3f3; display: block; }
            .pfu-icon { width: 36px; height: 36px; opacity: .85; display: block; margin: 6px auto; }
            .pfu-code-block { background: #f7f7f7; padding: 8px; overflow: auto; }
        ';
    }

    /**
     * Register admin menu: main page + subpages (Library for all, Settings for admins)
     */
    public static function register_menu(): void
    {
        $cap_library  = 'read';
        $cap_settings = 'manage_options';

        add_menu_page(
            __('Private Uploader', 'pfu'),
            __('Private Uploader', 'pfu'),
            $cap_library,
            'pfu-overview',
            [__CLASS__, 'render_overview_page'],
            'dashicons-upload',
            27
        );

        // Sub: Overview
        add_submenu_page(
            'pfu-overview',
            __('Overview', 'pfu'),
            __('Overview', 'pfu'),
            $cap_library,
            'pfu-overview',
            [__CLASS__, 'render_overview_page']
        );

        // Sub: Library
        add_submenu_page(
            'pfu-overview',
            __('Library', 'pfu'),
            __('Library', 'pfu'),
            $cap_library,
            'pfu-library',
            [__CLASS__, 'render_library_page']
        );

        // Sub: Settings
        add_submenu_page(
            'pfu-overview',
            __('Settings', 'pfu'),
            __('Settings', 'pfu'),
            $cap_settings,
            'pfu-settings',
            [__CLASS__, 'render_settings_page']
        );

        // Hidden page: Safe Deactivate
        add_submenu_page(
            'pfu-overview',
            __('Safe Deactivate', 'pfu'),
            __('Safe Deactivate', 'pfu'),
            'manage_options',
            'pfu-safe-deactivate',
            [__CLASS__, 'render_safe_deactivate_page']
        );

        // Hide from sidebar but keep it routable
        add_action('admin_head', function () {
            remove_submenu_page('pfu-overview', 'pfu-safe-deactivate');
        });
    }

    /**
     * Register plugin settings
     */
    public static function register_settings(): void
    {
        register_setting(
            'pfu_settings_group',
            self::OPTION_KEY,
            ['sanitize_callback' => [__CLASS__, 'sanitize_settings']]
        );

        add_settings_section(
            'pfu_main',
            __('Upload policy', 'pfu'),
            [__CLASS__, 'render_settings_section'],
            'pfu-settings'
        );

        add_settings_field(
            'max_upload_bytes',
            __('Max upload size (bytes)', 'pfu'),
            [__CLASS__, 'render_field_max_upload_bytes'],
            'pfu-settings',
            'pfu_main'
        );

        add_settings_field(
            'allowed_mime_types',
            __('Allowed MIME types (one per line)', 'pfu'),
            [__CLASS__, 'render_field_allowed_mime_types'],
            'pfu-settings',
            'pfu_main'
        );
    }

    /**
     * Render settings section description
     */
    public static function render_settings_section(): void
    {
?>
        <p><?php esc_html_e('Configure max size and MIME allowlist for uploads handled by this plugin.', 'pfu'); ?></p>
    <?php
    }

    /**
     * Get plugin settings with defaults
     *
     * @return array Settings array
     */
    public static function get_settings(): array
    {
        $opt = get_option(self::OPTION_KEY, []);
        $defaults = [
            'max_upload_bytes'  => Plugin::DEFAULT_MAX_UPLOAD_BYTES,
            'allowed_mime_types' => Plugin::DEFAULT_ALLOWED_MIME,
        ];

        $opt['max_upload_bytes'] = isset($opt['max_upload_bytes']) ? (int) $opt['max_upload_bytes'] : $defaults['max_upload_bytes'];

        $mime = $opt['allowed_mime_types'] ?? $defaults['allowed_mime_types'];
        if (is_string($mime)) {
            $mime = preg_split('/\R+/', $mime) ?: [];
        }
        $mime = array_values(array_unique(array_filter(array_map('strval', (array)$mime))));
        $opt['allowed_mime_types'] = $mime ?: $defaults['allowed_mime_types'];

        return $opt + $defaults;
    }

    /**
     * Sanitize the settings array
     *
     * @param mixed $input Raw input from form
     * @return array Sanitized settings
     */
    public static function sanitize_settings($input): array
    {
        $out = [];

        $max = isset($input['max_upload_bytes']) ? (int)$input['max_upload_bytes'] : 0;
        if ($max <= 0) {
            $max = Plugin::DEFAULT_MAX_UPLOAD_BYTES;
        }
        $out['max_upload_bytes'] = $max;

        if (isset($input['allowed_mime_types'])) {
            $raw = is_array($input['allowed_mime_types'])
                ? $input['allowed_mime_types']
                : preg_split('/\R+/', (string) $input['allowed_mime_types']);

            $mime = array_values(
                array_unique(
                    array_filter(
                        array_map('trim', (array)$raw)
                    )
                )
            );

            $out['allowed_mime_types'] = $mime;
        }

        return $out;
    }

    /**
     * Render max upload bytes field
     */
    public static function render_field_max_upload_bytes(): void
    {
        $opt = self::get_settings();
    ?>
        <input type="number"
            name="<?php echo esc_attr(self::OPTION_KEY); ?>[max_upload_bytes]"
            value="<?php echo esc_attr($opt['max_upload_bytes']); ?>"
            min="1"
            step="1"
            class="regular-text" />
        <p class="description">
            <?php esc_html_e('Example: 52428800 for 50 MB', 'pfu'); ?>
        </p>
    <?php
    }

    /**
     * Render allowed MIME types field
     */
    public static function render_field_allowed_mime_types(): void
    {
        $opt = self::get_settings();
        $val = implode("\n", (array)$opt['allowed_mime_types']);
    ?>
        <textarea name="<?php echo esc_attr(self::OPTION_KEY); ?>[allowed_mime_types]"
            rows="6"
            class="large-text code"><?php echo esc_textarea($val); ?></textarea>
        <p class="description">
            <?php esc_html_e('One MIME per line, e.g. application/zip', 'pfu'); ?>
        </p>
    <?php
    }

    /**
     * Render Safe Deactivate page
     */
    public static function render_safe_deactivate_page(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'pfu'));
        }

        $root = Plugin::storage_root_base();
        $htaccess_path = trailingslashit($root) . '.htaccess';
        $web_config_path = trailingslashit($root) . 'web.config';
        $exists = is_dir($root);
        $nonce = wp_create_nonce('pfu_safe_deactivate');

    ?>
        <div class="wrap">
            <h1><?php esc_html_e('Safe Deactivate – Private Uploader', 'pfu'); ?></h1>

            <?php if (!$exists): ?>
                <p class="description">
                    <?php esc_html_e('Storage directory not found; nothing to clean.', 'pfu'); ?>
                </p>
            <?php else: ?>
                <p>
                    <strong><?php esc_html_e('Storage directory', 'pfu'); ?>:</strong>
                    <code><?php echo esc_html($root); ?></code>
                </p>
            <?php endif; ?>

            <p><?php esc_html_e('Choose what to do with stored files before deactivating the plugin.', 'pfu'); ?></p>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="pfu_safe_deactivate_handle" />
                <input type="hidden" name="_wpnonce" value="<?php echo esc_attr($nonce); ?>" />

                <table class="form-table">
                    <tbody>
                        <tr>
                            <th scope="row"><?php esc_html_e('Delete all files', 'pfu'); ?></th>
                            <td>
                                <label>
                                    <input type="radio" name="pfu_mode" value="delete" />
                                    <?php esc_html_e('Delete ALL user files from disk, then deactivate the plugin.', 'pfu'); ?>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('This cannot be undone. Consider backing up first.', 'pfu'); ?>
                                </p>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php esc_html_e('Keep files (block access)', 'pfu'); ?></th>
                            <td>
                                <label>
                                    <input type="radio" name="pfu_mode" value="deny" checked />
                                    <?php esc_html_e('Keep files on disk and block direct web access where possible.', 'pfu'); ?>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('We will attempt to create deny rules for Apache/IIS. For Nginx, add the snippet below to your server config.', 'pfu'); ?>
                                </p>

                                <?php
                                self::render_deny_rules_preview($htaccess_path, $web_config_path, $root);
                                ?>
                            </td>
                        </tr>
                    </tbody>
                </table>

                <?php submit_button(__('Proceed and deactivate', 'pfu')); ?>
                <a class="button button-secondary" href="<?php echo esc_url(admin_url('plugins.php')); ?>">
                    <?php esc_html_e('Cancel', 'pfu'); ?>
                </a>
            </form>
        </div>
    <?php
    }

    /**
     * Render deny rules preview for Apache, IIS, and Nginx
     *
     * @param string $htaccess_path Path to .htaccess
     * @param string $web_config_path Path to web.config
     * @param string $root Root directory
     */
    private static function render_deny_rules_preview(string $htaccess_path, string $web_config_path, string $root): void
    {
    ?>
        <h4><?php esc_html_e('Apache (.htaccess)', 'pfu'); ?></h4>
        <pre class="pfu-code-block"><code><?php echo esc_html("Options -Indexes\nRequire all denied"); ?></code></pre>
        <p class="description">
            <?php esc_html_e('Target:', 'pfu'); ?>
            <code><?php echo esc_html($htaccess_path); ?></code>
        </p>

        <h4><?php esc_html_e('IIS (web.config)', 'pfu'); ?></h4>
        <pre class="pfu-code-block"><code><?php
                                            echo esc_html('<configuration>
  <system.webServer>
    <security>
      <authorization>
        <remove users="*" roles="" verbs="" />
        <add accessType="Deny" users="*" />
      </authorization>
    </security>
    <directoryBrowse enabled="false" />
  </system.webServer>
</configuration>');
                                            ?></code></pre>
        <p class="description">
            <?php esc_html_e('Target:', 'pfu'); ?>
            <code><?php echo esc_html($web_config_path); ?></code>
        </p>

        <h4><?php esc_html_e('Nginx (add to server config)', 'pfu'); ?></h4>
        <pre class="pfu-code-block"><code><?php
                                            $nginx_location = trailingslashit(str_replace(ABSPATH, '/', $root));
                                            echo esc_html("location ^~ {$nginx_location} {\n    deny all;\n}");
                                            ?></code></pre>
    <?php
    }

    /**
     * Render Overview page
     */
    public static function render_overview_page(): void
    {
        if (!is_user_logged_in()) {
            wp_die(esc_html__('You must be logged in.', 'pfu'));
        }

        $max_bytes = Plugin::effective_max_upload_bytes();
        $mimes = Plugin::effective_allowed_mime_types();

    ?>
        <div class="wrap">
            <h1><?php esc_html_e('Private Uploader – Overview', 'pfu'); ?></h1>

            <p><?php esc_html_e('This plugin lets you upload files to your private area on this site. The rules below apply to uploads performed via the mobile app or REST API.', 'pfu'); ?></p>

            <div class="pfu-cards">
                <?php self::render_max_size_card($max_bytes); ?>
                <?php self::render_mime_types_card($mimes); ?>
            </div>

            <?php self::render_server_limits_card(); ?>

            <div class="pfu-actions">
                <a class="button button-primary" href="<?php echo esc_url(admin_url('admin.php?page=pfu-library')); ?>">
                    <?php esc_html_e('Open your Library', 'pfu'); ?>
                </a>
                <?php if (current_user_can('manage_options')): ?>
                    <a class="button" href="<?php echo esc_url(admin_url('admin.php?page=pfu-settings')); ?>">
                        <?php esc_html_e('Settings', 'pfu'); ?>
                    </a>
                <?php endif; ?>
            </div>
        </div>
    <?php
    }

    /**
     * Render max size card
     *
     * @param int $max_bytes Maximum upload size in bytes
     */
    private static function render_max_size_card(int $max_bytes): void
    {
    ?>
        <div class="pfu-card">
            <h2><?php esc_html_e('Max upload size', 'pfu'); ?></h2>
            <p>
                <strong><?php echo esc_html(Utils::human_bytes($max_bytes)); ?></strong>
                <span class="pfu-muted">(<?php echo esc_html(number_format($max_bytes)); ?> bytes)</span>
            </p>
            <p class="pfu-muted">
                <?php esc_html_e('Requests exceeding this limit will be rejected.', 'pfu'); ?>
            </p>
        </div>
    <?php
    }

    /**
     * Render MIME types card
     *
     * @param array $mimes Allowed MIME types
     */
    private static function render_mime_types_card(array $mimes): void
    {
    ?>
        <div class="pfu-card">
            <h2><?php esc_html_e('Allowed MIME types', 'pfu'); ?></h2>
            <?php if (empty($mimes)): ?>
                <p class="pfu-muted">
                    <?php esc_html_e('No MIME types configured.', 'pfu'); ?>
                </p>
            <?php else: ?>
                <ul class="pfu-list">
                    <?php foreach ($mimes as $mime): ?>
                        <li><code><?php echo esc_html($mime); ?></code></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            <p class="pfu-muted">
                <?php esc_html_e('Uploads with unsupported types will be rejected.', 'pfu'); ?>
            </p>
        </div>
    <?php
    }

    /**
     * Render server limits card
     */
    private static function render_server_limits_card(): void
    {
        $policy_max = Plugin::effective_max_upload_bytes();
        list($up_human, $up_bytes, $up_raw) = Utils::get_ini_pair('upload_max_filesize');
        list($post_human, $post_bytes, $post_raw) = Utils::get_ini_pair('post_max_size');
        list($mem_human, $mem_bytes, $mem_raw) = Utils::get_ini_pair('memory_limit');
        $max_uploads = @ini_get('max_file_uploads');
        $exec_time = @ini_get('max_execution_time');

        $warnings = [];
        if ($policy_max > 0 && $up_bytes > 0 && $up_bytes < $policy_max) {
            $warnings[] = 'upload_max_filesize';
        }
        if ($policy_max > 0 && $post_bytes > 0 && $post_bytes < $policy_max) {
            $warnings[] = 'post_max_size';
        }

    ?>
        <div class="pfu-server-limits">
            <h2 style="margin-top:0"><?php esc_html_e('Server limits (PHP)', 'pfu'); ?></h2>

            <table class="widefat striped" style="margin-top:8px">
                <tbody>
                    <tr>
                        <td><?php esc_html_e('upload_max_filesize', 'pfu'); ?></td>
                        <td>
                            <code><?php echo esc_html($up_raw); ?></code>
                            <span class="pfu-muted">(<?php echo esc_html($up_human); ?>)</span>
                        </td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('post_max_size', 'pfu'); ?></td>
                        <td>
                            <code><?php echo esc_html($post_raw); ?></code>
                            <span class="pfu-muted">(<?php echo esc_html($post_human); ?>)</span>
                        </td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('memory_limit', 'pfu'); ?></td>
                        <td>
                            <code><?php echo esc_html($mem_raw); ?></code>
                            <span class="pfu-muted">(<?php echo esc_html($mem_human); ?>)</span>
                        </td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('max_file_uploads', 'pfu'); ?></td>
                        <td><code><?php echo esc_html((string)$max_uploads); ?></code></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('max_execution_time', 'pfu'); ?></td>
                        <td>
                            <code><?php echo esc_html((string)$exec_time); ?></code>
                            <span class="pfu-muted"><?php esc_html_e('seconds', 'pfu'); ?></span>
                        </td>
                    </tr>
                </tbody>
            </table>

            <p class="pfu-muted" style="margin-top:8px">
                <?php esc_html_e('Note: PHP/server limits must also allow the requested size. If uploads fail for large files, raise both upload_max_filesize and post_max_size (and check web server/proxy limits).', 'pfu'); ?>
            </p>

            <?php if (!empty($warnings)): ?>
                <div class="pfu-warning-box">
                    <strong><?php esc_html_e('Warning:', 'pfu'); ?></strong>
                    <?php esc_html_e('Your PHP limits are below the plugin policy. Increase the following:', 'pfu'); ?>
                    <code><?php echo esc_html(implode(', ', $warnings)); ?></code>
                    <?php if ($policy_max > 0): ?>
                        – <?php esc_html_e('desired at least', 'pfu'); ?>:
                        <strong><?php echo esc_html(Utils::human_bytes($policy_max)); ?></strong>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    <?php
    }

    /**
     * Render Library page
     */
    public static function render_library_page(): void
    {
        if (!is_user_logged_in()) {
            wp_die(esc_html__('You must be logged in.', 'pfu'));
        }

        $user = wp_get_current_user();
        $base = Plugin::get_user_base($user);
        $files = self::get_user_files($base['path'], $base['url']);

    ?>
        <div class="wrap">
            <h1><?php esc_html_e('Your uploads', 'pfu'); ?></h1>

            <?php if (empty($files)): ?>
                <p><?php esc_html_e('You have not uploaded any files yet.', 'pfu'); ?></p>
            <?php else: ?>
                <?php self::render_files_table($files); ?>
            <?php endif; ?>
        </div>
    <?php
    }

    /**
     * Get user files from directory
     *
     * @param string $dir Directory path
     * @param string $url Base URL
     * @return array Array of file data
     */
    private static function get_user_files(string $dir, string $url): array
    {
        if (!is_dir($dir)) {
            return [];
        }

        $files = [];
        $dh = @opendir($dir);

        if (!$dh) {
            return [];
        }

        while (false !== ($entry = readdir($dh))) {
            // Skip special entries
            if (in_array($entry, ['.', '..', 'index.html'], true) || strpos($entry, "\0") !== false) {
                continue;
            }

            // Skip metadata and system files
            if (Utils::is_metadata_file($entry) || Utils::is_system_file($entry)) {
                continue;
            }

            $abs = $dir . DIRECTORY_SEPARATOR . $entry;

            if (is_link($abs) || !is_file($abs)) {
                continue;
            }

            $size = @filesize($abs);
            $mtime = @filemtime($abs);
            $filetype = wp_check_filetype($entry);
            $mime = !empty($filetype['type']) ? $filetype['type'] : 'application/octet-stream';

            $files[] = [
                'name' => $entry,
                'url' => $url . '/' . rawurlencode($entry),
                'size' => is_int($size) ? $size : 0,
                'mtime' => is_int($mtime) ? $mtime : 0,
                'mime' => $mime,
            ];
        }

        closedir($dh);

        // Sort by modification time (newest first)
        usort($files, fn($a, $b) => $b['mtime'] <=> $a['mtime']);

        return $files;
    }

    /**
     * Render files table
     *
     * @param array $files Array of file data
     */
    private static function render_files_table(array $files): void
    {
    ?>
        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th class="column-pfu-preview"><?php esc_html_e('Preview', 'pfu'); ?></th>
                    <th><?php esc_html_e('File', 'pfu'); ?></th>
                    <th><?php esc_html_e('Size', 'pfu'); ?></th>
                    <th><?php esc_html_e('Modified', 'pfu'); ?></th>
                    <th><?php esc_html_e('MIME', 'pfu'); ?></th>
                    <th><?php esc_html_e('Actions', 'pfu'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($files as $file): ?>
                    <?php self::render_file_row($file); ?>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php
    }

    /**
     * Render a single file row
     *
     * @param array $file File data
     */
    private static function render_file_row(array $file): void
    {
        $name = $file['name'];
        $url = $file['url'];
        $is_image = strpos($file['mime'], 'image/') === 0;
        $nonce = wp_create_nonce('pfu_del_' . $name);
        $delete_url = admin_url('admin-post.php?action=pfu_delete_file&file=' . rawurlencode($name) . '&_wpnonce=' . $nonce);

    ?>
        <tr>
            <td class="column-pfu-preview">
                <?php if ($is_image): ?>
                    <a href="<?php echo esc_url($url); ?>" target="_blank" rel="noopener">
                        <img class="pfu-thumb" src="<?php echo esc_url($url); ?>" alt="" loading="lazy" />
                    </a>
                <?php else: ?>
                    <?php
                    $icon = wp_mime_type_icon($file['mime']);
                    if (empty($icon)) {
                        $icon = wp_mime_type_icon('application/octet-stream');
                    }
                    ?>
                    <img class="pfu-icon" src="<?php echo esc_url($icon); ?>" alt="" loading="lazy" />
                <?php endif; ?>
            </td>
            <td>
                <a href="<?php echo esc_url($url); ?>" target="_blank" rel="noopener">
                    <?php echo esc_html($name); ?>
                </a>
            </td>
            <td><?php echo esc_html(Utils::human_bytes($file['size'])); ?></td>
            <td><?php echo esc_html(gmdate('Y-m-d H:i', $file['mtime'])); ?></td>
            <td><?php echo esc_html($file['mime']); ?></td>
            <td>
                <a class="button button-small"
                    href="<?php echo esc_url($delete_url); ?>"
                    onclick="return confirm('<?php echo esc_js(__('Delete this file?', 'pfu')); ?>');">
                    <?php esc_html_e('Delete', 'pfu'); ?>
                </a>
            </td>
        </tr>
    <?php
    }

    /**
     * Handle file deletion (admin-post action)
     */
    public static function handle_delete_file(): void
    {
        if (!is_user_logged_in()) {
            wp_die(esc_html__('You must be logged in.', 'pfu'));
        }

        $user = wp_get_current_user();
        $file = isset($_GET['file']) ? (string)$_GET['file'] : '';
        $nonce = isset($_GET['_wpnonce']) ? (string)$_GET['_wpnonce'] : '';

        if (!wp_verify_nonce($nonce, 'pfu_del_' . $file)) {
            Utils::log_warning('Delete file failed: invalid nonce', [
                'user' => $user->user_login,
                'file' => $file
            ]);
            wp_die(esc_html__('Invalid nonce.', 'pfu'));
        }

        $base_file = Plugin::sanitize_user_filename($file);
        if (is_wp_error($base_file)) {
            Utils::log_warning('Delete file failed: invalid filename', [
                'user' => $user->user_login,
                'file' => $file,
                'error' => $base_file->get_error_message()
            ]);
            wp_die(esc_html($base_file->get_error_message()));
        }

        $paths = Plugin::get_user_base($user);
        $abs = $paths['path'] . DIRECTORY_SEPARATOR . $base_file;

        if (!file_exists($abs) || !is_file($abs)) {
            Utils::log_warning('Delete file failed: file not found', [
                'user' => $user->user_login,
                'file' => $base_file
            ]);
            wp_redirect(admin_url('admin.php?page=pfu-library&pfu_msg=notfound'));
            exit;
        }

        if (!Utils::is_path_within_base($paths['path'], $abs) || is_link($abs)) {
            Utils::log_error('Delete file failed: security check', [
                'user' => $user->user_login,
                'file' => $base_file,
                'path' => $abs
            ]);
            wp_die(esc_html__('Invalid path.', 'pfu'));
        }

        $ok = Utils::delete_file_with_metadata($abs);

        if ($ok) {
            Utils::log_info('File deleted via admin', [
                'user' => $user->user_login,
                'file' => $base_file
            ]);
        } else {
            Utils::log_error('Delete file failed: unlink error', [
                'user' => $user->user_login,
                'file' => $base_file
            ]);
        }

        $msg = $ok ? 'deleted' : 'delerror';
        wp_redirect(admin_url('admin.php?page=pfu-library&pfu_msg=' . $msg));
        exit;
    }

    /**
     * Handle safe deactivation
     */
    public static function handle_safe_deactivate(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission.', 'pfu'));
        }

        check_admin_referer('pfu_safe_deactivate');

        $mode = isset($_POST['pfu_mode']) ? (string)$_POST['pfu_mode'] : 'deny';
        $root = Plugin::storage_root_base();

        Utils::log_info('Safe deactivate initiated', [
            'mode' => $mode,
            'root' => $root
        ]);

        if ($mode === 'delete') {
            $size_before = Utils::get_directory_size($root);
            $files_count = Utils::count_directory_files($root, true);

            Utils::recursive_rmdir($root);

            Utils::log_info('Storage deleted during deactivation', [
                'size_deleted' => Utils::human_bytes($size_before),
                'files_deleted' => $files_count
            ]);

            $msg = 'pfu_deleted';
        } else {
            // Write deny rules for Apache/IIS if possible
            if (is_dir($root) && is_writable($root)) {
                $htaccess_content = "Options -Indexes\nRequire all denied\n";
                $web_config_content = "<configuration>\n  <system.webServer>\n    <security>\n      <authorization>\n        <remove users=\"*\" roles=\"\" verbs=\"\" />\n        <add accessType=\"Deny\" users=\"*\" />\n      </authorization>\n    </security>\n    <directoryBrowse enabled=\"false\" />\n  </system.webServer>\n</configuration>\n";

                @file_put_contents(trailingslashit($root) . '.htaccess', $htaccess_content);
                @file_put_contents(trailingslashit($root) . 'web.config', $web_config_content);
            }

            Utils::log_info('Deny rules written during deactivation', [
                'root' => $root
            ]);

            $msg = 'pfu_denied';
        }

        // Deactivate plugin programmatically
        deactivate_plugins(plugin_basename(PFU_PLUGIN_FILE));

        // Redirect back to Plugins screen with admin notice
        $url = add_query_arg('pfu_notice', $msg, admin_url('plugins.php'));
        wp_redirect($url);
        exit;
    }

    /**
     * Render Settings page
     */
    public static function render_settings_page(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'pfu'));
        }

    ?>
        <div class="wrap">
            <h1><?php esc_html_e('Private Uploader – Settings', 'pfu'); ?></h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('pfu_settings_group');
                do_settings_sections('pfu-settings');
                submit_button();
                ?>
            </form>
        </div>
    <?php
    }

    /**
     * Render user deletion form options
     *
     * @param \WP_User $user User being deleted
     */
    public static function delete_user_form($user): void
    {
        if (!current_user_can('delete_users')) {
            return;
        }

        $nonce = wp_create_nonce('pfu_delete_user_files_' . (int)$user->ID);

        // Calculate IDs to exclude (single user or bulk)
        $exclude_ids = [];
        if (isset($_REQUEST['user'])) {
            $exclude_ids[] = (int) $_REQUEST['user'];
        }
        if (!empty($_REQUEST['users']) && is_array($_REQUEST['users'])) {
            foreach ($_REQUEST['users'] as $uid) {
                $exclude_ids[] = (int) $uid;
            }
        }
        $exclude_ids = array_values(array_unique(array_filter($exclude_ids, fn($n) => $n > 0)));

    ?>
        <h2><?php esc_html_e('Private Uploader – User files', 'pfu'); ?></h2>
        <p><?php esc_html_e('Choose what to do with this user\'s uploaded files.', 'pfu'); ?></p>

        <input type="hidden" name="pfu_nonce" value="<?php echo esc_attr($nonce); ?>" />

        <fieldset class="pfu-box" style="border:1px solid #ccd0d4;padding:12px;max-width:680px;background:#fff">
            <label style="display:block;margin-bottom:8px">
                <input type="radio" name="pfu_user_files_action" value="delete" />
                <strong><?php esc_html_e('Delete all files', 'pfu'); ?></strong> –
                <?php esc_html_e('remove this user\'s storage directory permanently.', 'pfu'); ?>
            </label>

            <label style="display:block;margin-bottom:8px">
                <input type="radio" name="pfu_user_files_action" value="reassign" checked />
                <strong><?php esc_html_e('Reassign to another user', 'pfu'); ?></strong> –
                <?php esc_html_e('move the storage directory to the selected user.', 'pfu'); ?>
                <br />
                <?php
                wp_dropdown_users([
                    'name' => 'pfu_reassign_user',
                    'selected' => '0',
                    'option_none_value' => '0',
                    'show_option_none' => __('— Select user —', 'pfu'),
                    'exclude' => $exclude_ids,
                    'orderby' => 'user_login',
                    'order' => 'ASC',
                    'show' => 'user_login',
                    'include_selected' => true,
                    'who' => '',
                ]);
                ?>
            </label>

            <label style="display:block;margin-bottom:8px">
                <input type="radio" name="pfu_user_files_action" value="keep_deny" />
                <strong><?php esc_html_e('Keep files (no automatic blocking)', 'pfu'); ?></strong> –
                <?php esc_html_e('keep files on disk. You must manually add web server rules to block access (Apache/Nginx/IIS).', 'pfu'); ?>
            </label>
        </fieldset>
<?php
    }

    /**
     * Handle user deletion and process file actions
     *
     * @param int $user_id User ID being deleted
     */
    public static function handle_delete_user(int $user_id): void
    {
        if (!current_user_can('delete_users')) {
            return;
        }

        $action = isset($_POST['pfu_user_files_action']) ? (string)$_POST['pfu_user_files_action'] : '';
        $nonce = isset($_POST['pfu_nonce']) ? (string)$_POST['pfu_nonce'] : '';

        if (empty($action) || !wp_verify_nonce($nonce, 'pfu_delete_user_files_' . (int)$user_id)) {
            return;
        }

        $user = get_user_by('id', $user_id);
        if (!$user) {
            return;
        }

        $root = Plugin::storage_root_base();
        $src = $root . DIRECTORY_SEPARATOR . $user->user_login;

        if (!is_dir($src)) {
            return;
        }

        Utils::log_info('User deletion: processing files', [
            'user_id' => $user_id,
            'username' => $user->user_login,
            'action' => $action
        ]);

        switch ($action) {
            case 'delete':
                $size = Utils::get_directory_size($src);
                $count = Utils::count_directory_files($src, true);

                Utils::recursive_rmdir($src);

                Utils::log_info('User files deleted', [
                    'user_id' => $user_id,
                    'username' => $user->user_login,
                    'size_deleted' => Utils::human_bytes($size),
                    'files_deleted' => $count
                ]);

                set_transient('pfu_notice_users', 'deleted_ok', 60);
                break;

            case 'reassign':
                $to_id = isset($_POST['pfu_reassign_user']) ? (int)$_POST['pfu_reassign_user'] : 0;
                $to = $to_id ? get_user_by('id', $to_id) : null;

                if ($to && $to->user_login) {
                    $dst = $root . DIRECTORY_SEPARATOR . $to->user_login;

                    // If destination exists, rename with timestamp suffix
                    if (is_dir($dst)) {
                        $suffix = '-' . gmdate('YmdHis');
                        $dst = $dst . $suffix;
                    }

                    @rename($src, $dst);

                    Utils::log_info('User files reassigned', [
                        'from_user_id' => $user_id,
                        'from_username' => $user->user_login,
                        'to_user_id' => $to_id,
                        'to_username' => $to->user_login,
                        'destination' => $dst
                    ]);
                }

                set_transient('pfu_notice_users', 'reassigned_ok', 60);
                break;

            case 'keep_deny':
                Utils::log_info('User files kept (manual deny rules required)', [
                    'user_id' => $user_id,
                    'username' => $user->user_login,
                    'path' => $src
                ]);

                set_transient('pfu_notice_users', 'kept_manual_rules', 60);
                break;
        }
    }

    /**
     * Hook to display admin notices on users.php after user deletion
     */
    public static function maybe_hook_users_notice(): void
    {
        $code = get_transient('pfu_notice_users');
        if (!$code) {
            return;
        }

        add_action('admin_notices', function () use ($code) {
            $messages = [
                'kept_manual_rules' => [
                    'type' => 'warning',
                    'text' => __('Private Uploader: files were kept. Please add deny rules to your web server manually (Apache/Nginx/IIS) to block public access.', 'pfu')
                ],
                'reassigned_ok' => [
                    'type' => 'success',
                    'text' => __('Private Uploader: user files have been reassigned.', 'pfu')
                ],
                'deleted_ok' => [
                    'type' => 'success',
                    'text' => __('Private Uploader: user files have been deleted.', 'pfu')
                ]
            ];

            if (isset($messages[$code])) {
                $msg = $messages[$code];
                printf(
                    '<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
                    esc_attr($msg['type']),
                    esc_html($msg['text'])
                );
            }
        }, 1);

        delete_transient('pfu_notice_users');
    }
}
