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
        \add_action('admin_menu', [__CLASS__, 'register_menu']);
        \add_action('admin_init', [__CLASS__, 'register_settings']);
        \add_action('admin_post_pfu_delete_file', [__CLASS__, 'handle_delete_file']);
        \add_action('admin_post_pfu_safe_deactivate_handle', [__CLASS__, 'handle_safe_deactivate']);

        // User deletion hooks (single site)
        \add_action('load-users.php', [__CLASS__, 'maybe_hook_users_notice']);
        \add_action('delete_user_form', [__CLASS__, 'delete_user_form'], 10, 1);
        \add_action('delete_user', [__CLASS__, 'handle_delete_user'], 10, 1);

        // Multisite user deletion
        \add_action('wpmu_delete_user', [__CLASS__, 'handle_delete_user'], 10, 1);
    }

    /**
     * Register admin menu: main page + subpages (Library for all, Settings for admins)
     */
    public static function register_menu(): void
    {
        $capLibrary  = 'read';             // all logged-in users
        $capSettings = 'manage_options';   // admins only

        \add_menu_page(
            __('Private Uploader', 'pfu'),
            __('Private Uploader', 'pfu'),
            $capLibrary,
            'pfu-overview',
            [__CLASS__, 'render_overview_page'],
            'dashicons-upload',
            27
        );

        // Sub: Overview (duplicate so it appears as submenu)
        \add_submenu_page(
            'pfu-overview',
            __('Overview', 'pfu'),
            __('Overview', 'pfu'),
            $capLibrary,
            'pfu-overview',
            [__CLASS__, 'render_overview_page']
        );

        // Sub: Library (user's file list)
        \add_submenu_page(
            'pfu-overview',
            __('Library', 'pfu'),
            __('Library', 'pfu'),
            $capLibrary,
            'pfu-library',
            [__CLASS__, 'render_library_page']
        );

        // Sub: Settings (admins only)
        \add_submenu_page(
            'pfu-overview',
            __('Settings', 'pfu'),
            __('Settings', 'pfu'),
            $capSettings,
            'pfu-settings',
            [__CLASS__, 'render_settings_page']
        );

        // Hidden page: Safe Deactivate (admins only)
        \add_submenu_page(
            'pfu-overview',
            __('Safe Deactivate', 'pfu'),
            __('Safe Deactivate', 'pfu'),
            'manage_options',
            'pfu-safe-deactivate',
            [__CLASS__, 'render_safe_deactivate_page']
        );

        // Hide from sidebar but keep it routable
        \add_action('admin_head', function () {
            \remove_submenu_page('pfu-overview', 'pfu-safe-deactivate');
        });
    }

    /**
     * Register plugin settings (pfu_settings)
     */
    public static function register_settings(): void
    {
        \register_setting(
            'pfu_settings_group',
            self::OPTION_KEY,
            ['sanitize_callback' => [__CLASS__, 'sanitize_settings']]
        );

        \add_settings_section(
            'pfu_main',
            __('Upload policy', 'pfu'),
            function () {
                echo '<p>' . esc_html__('Configure max size and MIME allowlist for uploads handled by this plugin.', 'pfu') . '</p>';
            },
            'pfu-settings'
        );

        \add_settings_field(
            'max_upload_bytes',
            __('Max upload size (bytes)', 'pfu'),
            [__CLASS__, 'field_max_upload_bytes'],
            'pfu-settings',
            'pfu_main'
        );

        \add_settings_field(
            'allowed_mime_types',
            __('Allowed MIME types (one per line)', 'pfu'),
            [__CLASS__, 'field_allowed_mime_types'],
            'pfu-settings',
            'pfu_main'
        );
    }

    /**
     * Get plugin settings with defaults
     *
     * @return array Settings array
     */
    public static function get_settings(): array
    {
        $opt = \get_option(self::OPTION_KEY, []);
        $defaults = [
            'max_upload_bytes'  => Plugin::DEFAULT_MAX_UPLOAD_BYTES,
            'allowed_mime_types' => Plugin::DEFAULT_ALLOWED_MIME,
        ];

        // Normalize max_upload_bytes
        $opt['max_upload_bytes'] = isset($opt['max_upload_bytes']) ? (int) $opt['max_upload_bytes'] : $defaults['max_upload_bytes'];

        // Normalize allowed_mime_types
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
            $raw = [];
            if (is_array($input['allowed_mime_types'])) {
                $raw = $input['allowed_mime_types'];
            } else {
                $lines = preg_split('/\R+/', (string) $input['allowed_mime_types']);
                $raw   = is_array($lines) ? $lines : [];
            }
            $mime = array_values(
                array_unique(
                    array_filter(
                        array_map('trim', $raw)
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
    public static function field_max_upload_bytes(): void
    {
        $opt = self::get_settings();
        printf(
            '<input type="number" name="%s[max_upload_bytes]" value="%d" min="1" step="1" class="regular-text" />',
            esc_attr(self::OPTION_KEY),
            (int)$opt['max_upload_bytes']
        );
        echo '<p class="description">' . esc_html__('Example: 52428800 for 50 MB', 'pfu') . '</p>';
    }

    /**
     * Render allowed MIME types field
     */
    public static function field_allowed_mime_types(): void
    {
        $opt = self::get_settings();
        $val = implode("\n", (array)$opt['allowed_mime_types']);
        printf(
            '<textarea name="%s[allowed_mime_types]" rows="6" class="large-text code">%s</textarea>',
            esc_attr(self::OPTION_KEY),
            esc_textarea($val)
        );
        echo '<p class="description">' . esc_html__('One MIME per line, e.g. application/zip', 'pfu') . '</p>';
    }

    /**
     * Render Safe Deactivate page
     */
    public static function render_safe_deactivate_page(): void
    {
        if (!\current_user_can('manage_options')) {
            \wp_die(esc_html__('You do not have permission to access this page.', 'pfu'));
        }

        $root = \PFU\Plugin::storage_root_base();
        $htaccessPath = trailingslashit($root) . '.htaccess';
        $webConfigPath = trailingslashit($root) . 'web.config';
        $exists = is_dir($root);

        $nonce = \wp_create_nonce('pfu_safe_deactivate');

        echo '<div class="wrap"><h1>' . esc_html__('Safe Deactivate – Private Uploader', 'pfu') . '</h1>';

        if (!$exists) {
            echo '<p class="description">' . esc_html__('Storage directory not found; nothing to clean.', 'pfu') . '</p>';
        } else {
            echo '<p><strong>' . esc_html__('Storage directory', 'pfu') . ':</strong> <code>' . esc_html($root) . '</code></p>';
        }

        echo '<p>' . esc_html__('Choose what to do with stored files before deactivating the plugin.', 'pfu') . '</p>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="pfu_safe_deactivate_handle" />';
        echo '<input type="hidden" name="_wpnonce" value="' . esc_attr($nonce) . '" />';

        echo '<table class="form-table"><tbody>';

        // Option A: Delete everything
        echo '<tr><th scope="row">' . esc_html__('Delete all files', 'pfu') . '</th><td>';
        echo '<label><input type="radio" name="pfu_mode" value="delete" /> ';
        echo esc_html__('Delete ALL user files from disk, then deactivate the plugin.', 'pfu') . '</label>';
        echo '<p class="description">' . esc_html__('This cannot be undone. Consider backing up first.', 'pfu') . '</p>';
        echo '</td></tr>';

        // Option B: Keep files, write deny rules
        echo '<tr><th scope="row">' . esc_html__('Keep files (block access)', 'pfu') . '</th><td>';
        echo '<label><input type="radio" name="pfu_mode" value="deny" checked /> ';
        echo esc_html__('Keep files on disk and block direct web access where possible.', 'pfu') . '</label>';
        echo '<p class="description">' . esc_html__('We will attempt to create deny rules for Apache/IIS. For Nginx, add the snippet below to your server config.', 'pfu') . '</p>';

        // Apache .htaccess preview
        echo '<h4>' . esc_html__('Apache (.htaccess)', 'pfu') . '</h4>';
        echo '<pre style="background:#f7f7f7;padding:8px;overflow:auto"><code>';
        echo esc_html("Options -Indexes\nRequire all denied\n");
        echo "</code></pre>";
        echo '<p class="description">' . esc_html__('Target:', 'pfu') . ' <code>' . esc_html($htaccessPath) . '</code></p>';

        // IIS web.config preview
        echo '<h4>' . esc_html__('IIS (web.config)', 'pfu') . '</h4>';
        echo '<pre style="background:#f7f7f7;padding:8px;overflow:auto"><code>';
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
        echo "</code></pre>";
        echo '<p class="description">' . esc_html__('Target:', 'pfu') . ' <code>' . esc_html($webConfigPath) . '</code></p>';

        // Nginx snippet
        echo '<h4>' . esc_html__('Nginx (add to server config)', 'pfu') . '</h4>';
        echo '<pre style="background:#f7f7f7;padding:8px;overflow:auto"><code>';
        $escaped = "location ^~ " . trailingslashit(str_replace(ABSPATH, '/', $root)) . " {\n    deny all;\n}\n";
        echo esc_html($escaped);
        echo "</code></pre>";

        echo '</td></tr>';

        echo '</tbody></table>';

        submit_button(__('Proceed and deactivate', 'pfu'));
        echo ' <a class="button button-secondary" href="' . esc_url(admin_url('plugins.php')) . '">' . esc_html__('Cancel', 'pfu') . '</a>';

        echo '</form></div>';
    }

    /**
     * Render Overview page
     */
    public static function render_overview_page(): void
    {
        if (!\is_user_logged_in()) {
            \wp_die(esc_html__('You must be logged in.', 'pfu'));
        }

        // Get effective values (defaults → options → filters)
        $maxBytes = Plugin::effective_max_upload_bytes();
        $mimes    = Plugin::effective_allowed_mime_types();

        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('Private Uploader – Overview', 'pfu') . '</h1>';

        echo '<p>' . esc_html__(
            'This plugin lets you upload files to your private area on this site. The rules below apply to uploads performed via the mobile app or REST API.',
            'pfu'
        ) . '</p>';

        // Minimal styles
        echo '<style>
      .pfu-cards{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}
      .pfu-card{background:#fff;border:1px solid #e3e3e3;border-radius:8px;padding:16px;min-width:260px}
      .pfu-card h2{margin:0 0 8px;font-size:16px}
      .pfu-list{margin:8px 0 0 18px}
      .pfu-muted{color:#666}
      .pfu-actions{margin-top:16px}
    </style>';

        echo '<div class="pfu-cards">';

        // Card: Max size
        echo '<div class="pfu-card">';
        echo '<h2>' . esc_html__('Max upload size', 'pfu') . '</h2>';
        printf(
            '<p><strong>%s</strong> <span class="pfu-muted">(%d bytes)</span></p>',
            esc_html(self::human_size((int)$maxBytes)),
            (int)$maxBytes
        );
        echo '<p class="pfu-muted">' . esc_html__('Requests exceeding this limit will be rejected.', 'pfu') . '</p>';
        echo '</div>';

        // Card: Allowed MIME types
        echo '<div class="pfu-card">';
        echo '<h2>' . esc_html__('Allowed MIME types', 'pfu') . '</h2>';

        if (empty($mimes)) {
            echo '<p class="pfu-muted">' . esc_html__('No MIME types configured.', 'pfu') . '</p>';
        } else {
            echo '<ul class="pfu-list">';
            foreach ($mimes as $mt) {
                echo '<li><code>' . esc_html($mt) . '</code></li>';
            }
            echo '</ul>';
        }
        echo '<p class="pfu-muted">' . esc_html__('Uploads with unsupported types will be rejected.', 'pfu') . '</p>';
        echo '</div>';

        echo '</div>'; // .pfu-cards

        // Server-side limits card
        $policyMax = Plugin::effective_max_upload_bytes();

        // Read php.ini values at runtime
        list($upHuman,  $upBytes,  $upRaw)  = self::ini_pair('upload_max_filesize');
        list($postHuman, $postBytes, $postRaw) = self::ini_pair('post_max_size');
        list($memHuman, $memBytes, $memRaw) = self::ini_pair('memory_limit');
        $maxUploads = @ini_get('max_file_uploads');
        $execTime   = @ini_get('max_execution_time');

        // Warnings if PHP limits are lower than policy
        $warns = [];
        if ($policyMax > 0 && $upBytes  > 0 && $upBytes  < $policyMax) $warns[] = 'upload_max_filesize';
        if ($policyMax > 0 && $postBytes > 0 && $postBytes < $policyMax) $warns[] = 'post_max_size';

        echo '<div style="margin-top:16px;background:#fff;border:1px solid #e3e3e3;border-radius:8px;padding:16px">';
        echo '<h2 style="margin-top:0">' . esc_html__('Server limits (PHP)', 'pfu') . '</h2>';

        echo '<table class="widefat striped" style="margin-top:8px">';
        echo '<tbody>';
        printf(
            '<tr><td>%s</td><td><code>%s</code> <span class="pfu-muted">(%s)</span></td></tr>',
            esc_html__('upload_max_filesize', 'pfu'),
            esc_html($upRaw),
            esc_html($upHuman)
        );
        printf(
            '<tr><td>%s</td><td><code>%s</code> <span class="pfu-muted">(%s)</span></td></tr>',
            esc_html__('post_max_size', 'pfu'),
            esc_html($postRaw),
            esc_html($postHuman)
        );
        printf(
            '<tr><td>%s</td><td><code>%s</code> <span class="pfu-muted">(%s)</span></td></tr>',
            esc_html__('memory_limit', 'pfu'),
            esc_html($memRaw),
            esc_html($memHuman)
        );
        printf(
            '<tr><td>%s</td><td><code>%s</code></td></tr>',
            esc_html__('max_file_uploads', 'pfu'),
            esc_html((string)$maxUploads)
        );
        printf(
            '<tr><td>%s</td><td><code>%s</code> %s</td></tr>',
            esc_html__('max_execution_time', 'pfu'),
            esc_html((string)$execTime),
            '<span class="pfu-muted">' . esc_html__('seconds', 'pfu') . '</span>'
        );
        echo '</tbody></table>';

        // Explanatory note + warning
        echo '<p class="pfu-muted" style="margin-top:8px">';
        echo esc_html__('Note: PHP/server limits must also allow the requested size. If uploads fail for large files, raise both upload_max_filesize and post_max_size (and check web server/proxy limits).', 'pfu');
        echo '</p>';

        if (!empty($warns)) {
            echo '<div style="margin-top:8px;padding:8px 12px;border-left:4px solid #d63638;background:#fff3f3">';
            echo '<strong>' . esc_html__('Warning:', 'pfu') . '</strong> ';
            echo esc_html__('Your PHP limits are below the plugin policy. Increase the following:', 'pfu') . ' ';
            echo '<code>' . esc_html(implode(', ', $warns)) . '</code>';
            if ($policyMax > 0) {
                echo ' – ' . esc_html__('desired at least', 'pfu') . ': <strong>' . esc_html(self::human_size((int)$policyMax)) . '</strong>';
            }
            echo '</div>';
        }

        echo '</div>'; // card

        // Useful links
        echo '<div class="pfu-actions">';
        echo '<a class="button button-primary" href="' . esc_url(\admin_url('admin.php?page=pfu-library')) . '">'
            . esc_html__('Open your Library', 'pfu') . '</a> ';

        if (\current_user_can('manage_options')) {
            echo '<a class="button" href="' . esc_url(\admin_url('admin.php?page=pfu-settings')) . '">'
                . esc_html__('Settings', 'pfu') . '</a>';
        }
        echo '</div>';

        echo '</div>'; // .wrap
    }

    /**
     * Render Library page
     */
    public static function render_library_page(): void
    {
        if (!\is_user_logged_in()) {
            \wp_die(esc_html__('You must be logged in.', 'pfu'));
        }

        $user = \wp_get_current_user();
        $base = Plugin::get_user_base($user);
        $dir  = $base['path'];
        $url  = $base['url'];

        echo '<div class="wrap"><h1>' . esc_html__('Your uploads', 'pfu') . '</h1>';
        echo '<style>
            .column-pfu-preview{width:60px;}
            .pfu-thumb{width:48px;height:48px;object-fit:cover;border-radius:4px;background:#f3f3f3;display:block}
            .pfu-icon{width:36px;height:36px;opacity:.85;display:block;margin:6px auto}
            </style>';

        if (!is_dir($dir)) {
            echo '<p>' . esc_html__('You have not uploaded any files yet.', 'pfu') . '</p></div>';
            return;
        }

        // Scan directory
        $rows = [];
        $dh = @opendir($dir);
        if ($dh) {
            while (false !== ($entry = readdir($dh))) {
                if ($entry === '.' || $entry === '..' || $entry === 'index.html' || strpos($entry, "\0") !== false) {
                    continue;
                }
                $abs = $dir . DIRECTORY_SEPARATOR . $entry;
                if (\is_link($abs) || !is_file($abs)) continue;

                $size  = @filesize($abs);
                $mtime = @filemtime($abs);
                $ft    = \wp_check_filetype($entry);
                $mime  = ($ft && !empty($ft['type'])) ? $ft['type'] : 'application/octet-stream';

                $rows[] = [
                    'name' => $entry,
                    'url'  => $url . '/' . rawurlencode($entry),
                    'size' => is_int($size) ? $size : 0,
                    'mtime' => is_int($mtime) ? $mtime : 0,
                    'mime' => $mime,
                ];
            }
            closedir($dh);
        }

        if (empty($rows)) {
            echo '<p>' . esc_html__('No files found.', 'pfu') . '</p></div>';
            return;
        }

        // Sort by mtime desc
        usort($rows, fn($a, $b) => ($b['mtime'] <=> $a['mtime']));

        // Table
        echo '<table class="widefat fixed striped"><thead><tr>';
        echo '<th class="column-pfu-preview">' . esc_html__('Preview', 'pfu') . '</th>';
        echo '<th>' . esc_html__('File', 'pfu') . '</th>';
        echo '<th>' . esc_html__('Size', 'pfu') . '</th>';
        echo '<th>' . esc_html__('Modified', 'pfu') . '</th>';
        echo '<th>' . esc_html__('MIME', 'pfu') . '</th>';
        echo '<th>' . esc_html__('Actions', 'pfu') . '</th>';
        echo '</tr></thead><tbody>';

        foreach ($rows as $r) {
            $name = $r['name'];
            $view = esc_url($r['url']);
            $nonce = \wp_create_nonce('pfu_del_' . $name);
            $del  = \admin_url('admin-post.php?action=pfu_delete_file&file=' . rawurlencode($name) . '&_wpnonce=' . $nonce);

            $is_image = (strpos((string)$r['mime'], 'image/') === 0);
            $preview_html = '';
            if ($is_image) {
                // Use the file URL directly as a "soft" thumbnail (we don't have attachment ID)
                $preview_html = sprintf(
                    '<a href="%s" target="_blank" rel="noopener"><img class="pfu-thumb" src="%s" alt="" loading="lazy" /></a>',
                    esc_url($r['url']),
                    esc_url($r['url'])
                );
            } else {
                // WordPress default icon for MIME type
                $icon = \wp_mime_type_icon((string)$r['mime']);
                if (empty($icon)) {
                    // Generic fallback
                    $icon = \wp_mime_type_icon('application/octet-stream');
                }
                $preview_html = sprintf(
                    '<img class="pfu-icon" src="%s" alt="" loading="lazy" />',
                    esc_url($icon)
                );
            }

            printf(
                '<tr>
                <td class="column-pfu-preview">%1$s</td>
                <td><a href="%2$s" target="_blank" rel="noopener">%3$s</a></td>
                <td>%4$s</td>
                <td>%5$s</td>
                <td>%6$s</td>
                <td><a class="button button-small" href="%7$s" onclick="return confirm(\'%8$s\');">%9$s</a></td>
                </tr>',
                $preview_html,
                esc_url($r['url']),
                esc_html($r['name']),
                esc_html(self::human_size((int)$r['size'])),
                esc_html(gmdate('Y-m-d H:i', (int)$r['mtime'])),
                esc_html((string)$r['mime']),
                esc_url($del),
                esc_js(__('Delete this file?', 'pfu')),
                esc_html__('Delete', 'pfu')
            );
        }

        echo '</tbody></table></div>';
    }

    /**
     * Handle file deletion (admin-post action, no JS needed)
     */
    public static function handle_delete_file(): void
    {
        if (!\is_user_logged_in()) {
            \wp_die(esc_html__('You must be logged in.', 'pfu'));
        }

        $user = \wp_get_current_user();
        $file = isset($_GET['file']) ? (string)$_GET['file'] : '';
        $nonce = isset($_GET['_wpnonce']) ? (string)$_GET['_wpnonce'] : '';

        if (!\wp_verify_nonce($nonce, 'pfu_del_' . $file)) {
            \wp_die(esc_html__('Invalid nonce.', 'pfu'));
        }

        $baseFile = Plugin::sanitize_user_filename($file);
        if (\is_wp_error($baseFile)) {
            \wp_die(esc_html($baseFile->get_error_message()));
        }

        $paths = Plugin::get_user_base($user);
        $abs   = $paths['path'] . DIRECTORY_SEPARATOR . $baseFile;

        if (!file_exists($abs) || !is_file($abs)) {
            \wp_redirect(\admin_url('admin.php?page=pfu-library&pfu_msg=notfound'));
            exit;
        }

        if (!Plugin::path_within_base($paths['path'], $abs) || \is_link($abs)) {
            \wp_die(esc_html__('Invalid path.', 'pfu'));
        }

        $ok = @unlink($abs);
        $msg = $ok ? 'deleted' : 'delerror';
        \wp_redirect(\admin_url('admin.php?page=pfu-library&pfu_msg=' . $msg));
        exit;
    }

    /**
     * Handle safe deactivation
     */
    public static function handle_safe_deactivate(): void
    {
        if (!\current_user_can('manage_options')) {
            \wp_die(esc_html__('You do not have permission.', 'pfu'));
        }
        \check_admin_referer('pfu_safe_deactivate');

        $mode = isset($_POST['pfu_mode']) ? (string)$_POST['pfu_mode'] : 'deny';
        $root = \PFU\Plugin::storage_root_base();

        if ($mode === 'delete') {
            self::rrmdir($root);
            $msg = 'pfu_deleted';
        } else {
            // Write deny rules for Apache/IIS if possible
            if (is_dir($root) && is_writable($root)) {
                @file_put_contents(trailingslashit($root) . '.htaccess', "Options -Indexes\nRequire all denied\n");
                @file_put_contents(trailingslashit($root) . 'web.config', "<configuration>\n  <system.webServer>\n    <security>\n      <authorization>\n        <remove users=\"*\" roles=\"\" verbs=\"\" />\n        <add accessType=\"Deny\" users=\"*\" />\n      </authorization>\n    </security>\n    <directoryBrowse enabled=\"false\" />\n  </system.webServer>\n</configuration>\n");
            }
            $msg = 'pfu_denied';
        }

        // Deactivate plugin programmatically
        \deactivate_plugins(plugin_basename(PFU_PLUGIN_FILE));

        // Redirect back to Plugins screen with admin notice
        $url = add_query_arg('pfu_notice', $msg, admin_url('plugins.php'));
        \wp_redirect($url);
        exit;
    }

    /**
     * Recursive delete of a directory
     *
     * @param string $dir Directory path
     */
    private static function rrmdir(string $dir): void
    {
        if (!is_dir($dir)) return;
        $items = @scandir($dir);
        if (!is_array($items)) return;
        foreach ($items as $it) {
            if ($it === '.' || $it === '..') continue;
            $p = $dir . DIRECTORY_SEPARATOR . $it;
            if (is_link($p)) {
                @unlink($p);
                continue;
            }
            if (is_dir($p)) {
                self::rrmdir($p);
                continue;
            }
            @unlink($p);
        }
        @rmdir($dir);
    }

    /**
     * Render Settings page
     */
    public static function render_settings_page(): void
    {
        if (!\current_user_can('manage_options')) {
            \wp_die(esc_html__('You do not have permission to access this page.', 'pfu'));
        }
        echo '<div class="wrap"><h1>' . esc_html__('Private Uploader – Settings', 'pfu') . '</h1>';
        echo '<form method="post" action="options.php">';
        \settings_fields('pfu_settings_group');
        \do_settings_sections('pfu-settings');
        \submit_button();
        echo '</form></div>';
    }

    /**
     * Convert bytes to human-readable format
     *
     * @param int $bytes Number of bytes
     * @return string Human-readable size
     */
    private static function human_size(int $bytes): string
    {
        $u = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        $n = $bytes;
        while ($n >= 1024 && $i < count($u) - 1) {
            $n /= 1024;
            $i++;
        }
        return ($i === 0) ? "$n {$u[$i]}" : number_format($n, 2) . " {$u[$i]}";
    }

    /**
     * Convert shorthand INI notation (e.g. "128M", "2G") to bytes
     *
     * @param mixed $val INI value
     * @return int Bytes
     */
    private static function ini_bytes($val): int
    {
        if ($val === null || $val === '') return 0;
        $v = trim((string)$val);
        if ($v === '-1') return PHP_INT_MAX; // unlimited
        if (preg_match('/^\d+$/', $v)) return (int)$v;
        if (!preg_match('/^\s*([0-9\.]+)\s*([KMGkmg])\s*$/', $v, $m)) return (int)$v;
        $n = (float)$m[1];
        $u = strtoupper($m[2]);
        switch ($u) {
            case 'G':
                $n *= 1024;
                // no break
            case 'M':
                $n *= 1024;
                // no break
            case 'K':
                $n *= 1024;
        }
        return (int)round($n);
    }

    /**
     * Get INI value as [human_readable, bytes, raw_value] tuple
     *
     * @param string $key INI key
     * @return array [human_readable, bytes, raw_value]
     */
    private static function ini_pair(string $key): array
    {
        $raw = @ini_get($key);
        $bytes = self::ini_bytes($raw);
        $human = ($raw === false || $raw === '') ? 'N/A' : ($raw === '-1' ? __('Unlimited', 'pfu') : self::human_size($bytes));
        return [$human, $bytes, (string)$raw];
    }

    /**
     * Render user deletion form options
     *
     * @param \WP_User $user User being deleted
     */
    public static function delete_user_form($user): void
    {
        if (!\current_user_can('delete_users')) return;

        $nonce = \wp_create_nonce('pfu_delete_user_files_' . (int)$user->ID);

        echo '<h2>' . esc_html__('Private Uploader – User files', 'pfu') . '</h2>';
        echo '<p>' . esc_html__('Choose what to do with this user\'s uploaded files.', 'pfu') . '</p>';

        echo '<input type="hidden" name="pfu_nonce" value="' . esc_attr($nonce) . '" />';

        echo '<fieldset class="pfu-box" style="border:1px solid #ccd0d4;padding:12px;max-width:680px;background:#fff">';
        echo '<label style="display:block;margin-bottom:8px">';
        echo '<input type="radio" name="pfu_user_files_action" value="delete" /> ';
        echo '<strong>' . esc_html__('Delete all files', 'pfu') . '</strong> – ';
        echo esc_html__('remove this user\'s storage directory permanently.', 'pfu');
        echo '</label>';

        echo '<label style="display:block;margin-bottom:8px">';
        echo '<input type="radio" name="pfu_user_files_action" value="reassign" checked /> ';
        echo '<strong>' . esc_html__('Reassign to another user', 'pfu') . '</strong> – ';
        echo esc_html__('move the storage directory to the selected user.', 'pfu');
        echo '<br />';

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

        // "No selection" value
        $none_value = '0';

        // User dropdown: no default selection, exclude IDs being deleted
        \wp_dropdown_users([
            'name'               => 'pfu_reassign_user',
            'selected'           => $none_value,
            'option_none_value'  => $none_value,
            'show_option_none'   => __('— Select user —', 'pfu'),
            'exclude'            => $exclude_ids,
            'orderby'            => 'user_login',
            'order'              => 'ASC',
            'show'               => 'user_login',
            'include_selected'   => true,
            'who'                => '',
        ]);

        echo '</label>';

        // Keep with deny option
        echo '<label style="display:block;margin-bottom:8px">';
        echo '<input type="radio" name="pfu_user_files_action" value="keep_deny" /> ';
        echo '<strong>' . esc_html__('Keep files (no automatic blocking)', 'pfu') . '</strong> – ';
        echo esc_html__('keep files on disk. You must manually add web server rules to block access (Apache/Nginx/IIS).', 'pfu');
        echo '</label>';

        echo '</fieldset>';
    }

    /**
     * Handle user deletion and process file actions
     *
     * @param int $user_id User ID being deleted
     */
    public static function handle_delete_user(int $user_id): void
    {
        if (!\current_user_can('delete_users')) return;

        $action = isset($_POST['pfu_user_files_action']) ? (string)$_POST['pfu_user_files_action'] : '';
        $nonce  = isset($_POST['pfu_nonce']) ? (string)$_POST['pfu_nonce'] : '';
        if (empty($action) || !\wp_verify_nonce($nonce, 'pfu_delete_user_files_' . (int)$user_id)) {
            return; // no choice or missing nonce → don't touch anything
        }

        $user = \get_user_by('id', $user_id);
        if (!$user) return;

        $root = \PFU\Plugin::storage_root_base();
        $src  = $root . DIRECTORY_SEPARATOR . $user->user_login;

        if (!is_dir($src)) return; // no storage → nothing to do

        if ($action === 'delete') {
            self::rrmdir($src);
            set_transient('pfu_notice_users', 'deleted_ok', 60);
            return;
        }

        if ($action === 'reassign') {
            $to_id = isset($_POST['pfu_reassign_user']) ? (int)$_POST['pfu_reassign_user'] : 0;
            $to    = $to_id ? \get_user_by('id', $to_id) : null;
            if ($to && $to->user_login) {
                $dst = $root . DIRECTORY_SEPARATOR . $to->user_login;

                // If destination exists, merge into subfolder or rename with suffix
                if (is_dir($dst)) {
                    $suffix = '-' . gmdate('YmdHis');
                    $dst = $dst . $suffix;
                }

                @rename($src, $dst);
            }
            set_transient('pfu_notice_users', 'reassigned_ok', 60);
            return;
        }

        if ($action === 'keep_deny') {
            // Don't write rules automatically. Show a notice after redirect.
            set_transient('pfu_notice_users', 'kept_manual_rules', 60);
            return;
        }
    }

    /**
     * Hook to display admin notices on users.php after user deletion
     */
    public static function maybe_hook_users_notice(): void
    {
        // Only execute when loading users.php
        $code = get_transient('pfu_notice_users');
        if (!$code) return;

        // Register notice for this request only, then delete transient
        add_action('admin_notices', function () use ($code) {
            if ($code === 'kept_manual_rules') {
                echo '<div class="notice notice-warning is-dismissible"><p>'
                    . esc_html__('Private Uploader: files were kept. Please add deny rules to your web server manually (Apache/Nginx/IIS) to block public access.', 'pfu')
                    . '</p></div>';
            } elseif ($code === 'reassigned_ok') {
                echo '<div class="notice notice-success is-dismissible"><p>'
                    . esc_html__('Private Uploader: user files have been reassigned.', 'pfu')
                    . '</p></div>';
            } elseif ($code === 'deleted_ok') {
                echo '<div class="notice notice-success is-dismissible"><p>'
                    . esc_html__('Private Uploader: user files have been deleted.', 'pfu')
                    . '</p></div>';
            }
        }, 1);

        delete_transient('pfu_notice_users');
    }
}
