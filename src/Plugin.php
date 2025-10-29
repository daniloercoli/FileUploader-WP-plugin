<?php

namespace PFU;

if (!defined('ABSPATH')) {
    exit;
}

class Plugin
{
    const REST_NS   = 'fileuploader/v1';
    const TEXT_DOMAIN = 'pfu';
    const SLUG      = 'private-file-uploader';
    const SUB_BASE  = 'media/private-file-uploader'; // under uploads/

    // Default values; overridable via filters (see below)
    const DEFAULT_MAX_UPLOAD_BYTES = 50 * 1024 * 1024; // 50 MB
    const DEFAULT_ALLOWED_MIME = [
        'application/zip',
        'image/jpeg',
        'image/png',
        'application/pdf',
    ];

    /**
     * Get the storage root base directory
     *
     * @return string Absolute path to the storage root
     */
    public static function storage_root_base(): string
    {
        $up = \wp_get_upload_dir();
        return trailingslashit($up['basedir']) . self::SUB_BASE;
    }

    /**
     * Get the effective max upload size (defaults → options → filters)
     *
     * @return int Maximum upload size in bytes
     */
    public static function effective_max_upload_bytes(): int
    {
        return self::get_max_upload_bytes();
    }

    /**
     * Get the effective allowed MIME types (defaults → options → filters)
     *
     * @return array<string> List of allowed MIME types
     */
    public static function effective_allowed_mime_types(): array
    {
        return self::get_allowed_mime_types();
    }

    /**
     * Get the max upload size in bytes, configurable via 'pfu_max_upload_bytes' filter
     *
     * @return int Maximum upload size in bytes
     */
    private static function get_max_upload_bytes(): int
    {
        // 1) defaults
        $max = self::DEFAULT_MAX_UPLOAD_BYTES;

        // 2) options (admin settings)
        if (class_exists(__NAMESPACE__ . '\\Admin')) {
            $opt = Admin::get_settings();
            if (!empty($opt['max_upload_bytes']) && (int)$opt['max_upload_bytes'] > 0) {
                $max = (int)$opt['max_upload_bytes'];
            }
        }

        // 3) filters (can still override)
        $max = (int) apply_filters('pfu_max_upload_bytes', $max);
        return $max > 0 ? $max : self::DEFAULT_MAX_UPLOAD_BYTES;
    }

    /**
     * Get the allowed MIME types, configurable via 'pfu_allowed_mime_types' filter
     *
     * @return array<string> List of allowed MIME types
     */
    private static function get_allowed_mime_types(): array
    {
        // 1) defaults
        $allowed = self::DEFAULT_ALLOWED_MIME;

        // 2) options (admin settings)
        if (class_exists(__NAMESPACE__ . '\\Admin')) {
            $opt = Admin::get_settings();
            if (!empty($opt['allowed_mime_types']) && is_array($opt['allowed_mime_types'])) {
                $allowed = array_values(array_unique(array_filter(array_map('strval', $opt['allowed_mime_types']))));
            }
        }

        // 3) filters
        $m = apply_filters('pfu_allowed_mime_types', $allowed);
        if (!is_array($m) || empty($m)) {
            return $allowed;
        }
        return array_values(array_unique(array_filter(array_map('strval', $m))));
    }

    /**
     * Initialize the plugin
     */
    public static function init(): void
    {
        add_action('rest_api_init', [__CLASS__, 'register_routes']);
        // Load translations from /languages
        add_action('init', function () {
            load_plugin_textdomain(self::TEXT_DOMAIN, false, dirname(plugin_basename(__FILE__)) . '/languages');
        });
        Utils::log_debug('REST routes initialization scheduled');
    }

    /**
     * Register REST API routes
     */
    public static function register_routes(): void
    {
        // GET /ping - Authentication check
        register_rest_route(self::REST_NS, '/ping', [
            [
                'methods'  => 'GET',
                'callback' => [__CLASS__, 'route_ping'],
                'permission_callback' => [__CLASS__, 'require_auth'],
            ],
        ]);

        // POST /upload - Upload a single file
        register_rest_route(self::REST_NS, '/upload', [
            [
                'methods'  => 'POST',
                'callback' => [__CLASS__, 'route_upload'],
                'permission_callback' => [__CLASS__, 'require_can_upload'],
            ],
        ]);

        // GET /files - List user's files
        register_rest_route(self::REST_NS, '/files', [
            [
                'methods'  => 'GET',
                'callback' => [__CLASS__, 'route_list_files'],
                'permission_callback' => [__CLASS__, 'require_auth'],
                'args' => [
                    'page' => [
                        'description' => 'Page number (1-based)',
                        'type'        => 'integer',
                        'required'    => false,
                        'sanitize_callback' => 'absint',
                        'validate_callback' => static function ($value) {
                            return ($value === null) || (absint($value) >= 1);
                        },
                    ],
                    'per_page' => [
                        'description' => 'Items per page (1..1000)',
                        'type'        => 'integer',
                        'required'    => false,
                        'sanitize_callback' => 'absint',
                        'validate_callback' => static function ($value) {
                            $v = absint($value);
                            return $v >= 1 && $v <= 1000;
                        },
                    ],
                    'order' => [
                        'description' => 'Sort by modified time: desc|asc',
                        'type'        => 'string',
                        'required'    => false,
                        'sanitize_callback' => 'sanitize_text_field',
                        'validate_callback' => static function ($value) {
                            return in_array(strtolower((string)$value), ['asc', 'desc'], true);
                        },
                    ],
                ],
            ],
        ]);

        // DELETE /files/{filename} - Delete a user's file
        register_rest_route(self::REST_NS, '/files/(?P<filename>[^/]+)', [
            [
                'methods'  => 'DELETE',
                'callback' => [__CLASS__, 'route_delete_file'],
                'permission_callback' => [__CLASS__, 'require_can_upload'],
                'args' => [
                    'filename' => [
                        'description' => 'Base filename to delete (no slashes)',
                        'required' => true,
                        'sanitize_callback' => [__CLASS__, 'sanitize_user_filename'],
                        'validate_callback' => static function ($value) {
                            return is_string($value) && strpos($value, '/') === false;
                        },
                    ],
                ],
            ],
        ]);

        // HEAD /files/{filename} - Get file metadata via headers (no body)
        register_rest_route(self::REST_NS, '/files/(?P<filename>[^/]+)', [
            [
                'methods'  => 'HEAD',
                'callback' => [__CLASS__, 'route_head_file'],
                'permission_callback' => [__CLASS__, 'require_auth'],
                'args' => [
                    'filename' => [
                        'description' => 'Base filename to inspect (no slashes)',
                        'required' => true,
                        'sanitize_callback' => [__CLASS__, 'sanitize_user_filename'],
                        'validate_callback' => static function ($value) {
                            return is_string($value) && strpos($value, '/') === false;
                        },
                    ],
                ],
            ],
        ]);

        Utils::log_debug('REST routes registered', [
            'namespace' => self::REST_NS,
            'endpoints' => 5
        ]);
    }

    /**
     * Permission callback: require authentication (Application Password)
     *
     * @param \WP_REST_Request $req Current request
     * @return bool|\WP_Error True if authenticated, WP_Error otherwise
     */
    public static function require_auth(\WP_REST_Request $req)
    {
        if (is_user_logged_in()) {
            return true;
        }

        Utils::log_warning('Unauthorized access attempt', [
            'endpoint' => $req->get_route(),
            'ip' => Utils::get_client_ip()
        ]);

        return new \WP_Error('pfu_auth', 'Authentication required', ['status' => 401]);
    }

    /**
     * Permission callback: require authenticated user with upload capability
     *
     * @param \WP_REST_Request $req Current request
     * @return bool|\WP_Error True if authorized, WP_Error otherwise
     */
    public static function require_can_upload(\WP_REST_Request $req)
    {
        if (is_user_logged_in() && current_user_can('upload_files')) {
            return true;
        }

        Utils::log_warning('Forbidden access attempt - insufficient permissions', [
            'endpoint' => $req->get_route(),
            'user_id' => get_current_user_id(),
            'ip' => Utils::get_client_ip()
        ]);

        return new \WP_Error('pfu_forbidden', 'Insufficient permissions', ['status' => 403]);
    }

    /**
     * GET /ping - Useful for testing credentials via curl
     *
     * @param \WP_REST_Request $req Current request
     * @return \WP_REST_Response Response with user info
     */
    public static function route_ping(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = wp_get_current_user();

        Utils::log_info('Ping endpoint accessed', [
            'user' => $user ? $user->user_login : 'guest',
            'ip' => Utils::get_client_ip(),
            'mobile' => Utils::is_mobile_request()
        ]);

        return new \WP_REST_Response([
            'ok'      => true,
            'user'    => $user ? $user->user_login : null,
            'message' => __('Hello from Private File Uploader', self::TEXT_DOMAIN),
        ]);
    }

    /**
     * POST /upload - Upload a single file (multipart field "file") to uploads/media/private-file-uploader/<username>/
     * Uses upload_dir filter (scoped) and wp_handle_sideload to move the file
     *
     * @param \WP_REST_Request $req Current request
     * @return \WP_REST_Response Upload result
     */
    public static function route_upload(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = wp_get_current_user();
        if (!$user || 0 === $user->ID) {
            Utils::log_error('Upload failed: user not authenticated');
            return new \WP_REST_Response(['ok' => false, 'error' => __('Not authenticated', self::TEXT_DOMAIN)], 401);
        }

        if (!self::check_rate_limit($user->ID)) {
            return new \WP_REST_Response([
                'ok' => false,
                'error' => 'Rate limit exceeded. Try again later.'
            ], 429);
        }
        // Get uploaded files from the request (WP maps them from $_FILES)
        $files = $req->get_file_params();

        // Expected field: "file" (as in curl -F 'file=@...')
        if (empty($files['file']) || !is_array($files['file'])) {
            // Fallback: first file if present
            if (is_array($files) && !empty($files)) {
                $first = reset($files);
                if (is_array($first)) {
                    $files['file'] = $first;
                }
            }
        }

        if (empty($files['file']) || !is_array($files['file'])) {
            Utils::log_warning('Upload rejected: no file provided');
            return new \WP_REST_Response(
                ['ok' => false, 'error' => 'No file provided (multipart field "file")'],
                400
            );
        }

        $original_filename = $files['file']['name'] ?? 'unknown';

        // Validations: max size + MIME allowlist
        $size = isset($files['file']['size']) ? (int)$files['file']['size'] : 0;
        $max  = self::get_max_upload_bytes();

        if ($size <= 0) {
            Utils::log_warning('Upload rejected: empty file', [
                'filename' => $original_filename
            ]);
            return new \WP_REST_Response(['ok' => false, 'error' => __('Empty upload or unknown size', self::TEXT_DOMAIN)], 400);
        }

        if ($size > $max) {
            Utils::log_warning('Upload rejected: file too large', [
                'filename' => $original_filename,
                'size' => $size,
                'limit' => $max,
                'size_human' => Utils::human_bytes($size),
                'limit_human' => Utils::human_bytes($max)
            ]);

            return new \WP_REST_Response([
                'ok'    => false,
                'error' => __('File too large', self::TEXT_DOMAIN),
                'limit' => $max,
                'limitHuman' => Utils::human_bytes($max),
                'got'   => $size,
                'gotHuman' => Utils::human_bytes($size),
            ], 413);
        }

        // MIME detection using Utils
        $allowed = self::get_allowed_mime_types();
        $mime = Utils::detect_mime_type($files['file']['tmp_name'], $original_filename);

        // Fallback to client header if detection failed
        if ($mime === null && !empty($files['file']['type'])) {
            $mime = (string)$files['file']['type'];
        }

        if ($mime === null || !in_array($mime, $allowed, true)) {
            Utils::log_warning('Upload rejected: unsupported MIME type', [
                'filename' => $original_filename,
                'mime' => $mime,
                'allowed' => $allowed
            ]);

            return new \WP_REST_Response([
                'ok'        => false,
                'error'     => __('Unsupported media type', self::TEXT_DOMAIN),
                'mime'      => $mime,
                'allowed'   => $allowed,
                'hint'      => 'Allowed MIME types can be configured via the pfu_allowed_mime_types filter.',
            ], 415);
        }

        $username = sanitize_user($user->user_login, true);
        if (empty($username)) {
            $username = 'user-' . $user->ID;
        }

        Utils::log_info('Upload started', [
            'user' => $username,
            'filename' => $original_filename,
            'size' => $size,
            'size_human' => Utils::human_bytes($size),
            'mime' => $mime,
            'ip' => Utils::get_client_ip(),
            'user_agent' => Utils::get_user_agent()
        ]);

        $subdir = '/' . self::SUB_BASE . '/' . $username;

        // Temporarily override upload directory
        $filter = function ($dirs) use ($subdir) {
            $basedir = isset($dirs['basedir']) ? $dirs['basedir'] : WP_CONTENT_DIR . '/uploads';
            $baseurl = isset($dirs['baseurl']) ? $dirs['baseurl'] : content_url('/uploads');

            $dirs['subdir'] = $subdir;
            $dirs['path']   = $basedir . $subdir;
            $dirs['url']    = $baseurl . $subdir;

            if (wp_mkdir_p($dirs['path'])) {
                self::ensure_index_html($dirs['path']);
            }
            return $dirs;
        };

        add_filter('upload_dir', $filter, 10, 1);

        $file_array = [
            'name'     => $files['file']['name'],
            'type'     => $files['file']['type'],
            'tmp_name' => $files['file']['tmp_name'],
            'error'    => $files['file']['error'],
            'size'     => $files['file']['size'],
        ];

        $overrides = ['test_form' => false];

        // Ensure upload functions are loaded
        if (!function_exists('\wp_handle_sideload')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        $moved = \wp_handle_sideload($file_array, $overrides);
        remove_filter('upload_dir', $filter, 10);

        if (isset($moved['error'])) {
            Utils::log_error('Upload failed during file handling', [
                'user' => $username,
                'filename' => $original_filename,
                'error' => $moved['error']
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => $moved['error']], 400);
        }

        $final_filename = wp_basename($moved['file']);

        // Save metadata
        Utils::save_file_metadata($moved['file'], [
            'original_name' => $original_filename,
            'mime' => $mime,
            'size' => $size,
            'ip' => Utils::get_client_ip(),
            'user_agent' => Utils::get_user_agent(),
            'mobile' => Utils::is_mobile_request()
        ]);

        Utils::log_info('Upload completed successfully', [
            'user' => $username,
            'original_filename' => $original_filename,
            'final_filename' => $final_filename,
            'size' => $size,
            'mime' => $mime,
            'path' => $moved['file']
        ]);

        return new \WP_REST_Response([
            'ok'       => true,
            'file'     => $final_filename,
            'path'     => $moved['file'],
            'url'      => $moved['url'],
            'mime'     => $moved['type'],
            'owner'    => $username,
            'location' => self::SUB_BASE . '/' . $username,
        ], 201);
    }

    /**
     * GET /files - List files for the current user
     *
     * @param \WP_REST_Request $req Current request
     * @return \WP_REST_Response List of files with pagination
     */
    public static function route_list_files(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = \wp_get_current_user();
        if (!$user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => __('Not authenticated', self::TEXT_DOMAIN)], 401);
        }

        $base = self::get_user_base($user);
        $dir  = $base['path'];
        $url  = $base['url'];

        // Parse parameters
        $page     = max(1, (int)($req->get_param('page') ?: 1));
        $per_page = (int)($req->get_param('per_page') ?: 1000);
        if ($per_page < 1) {
            $per_page = 1;
        }
        if ($per_page > 1000) {
            $per_page = 1000;
        }
        $order = strtolower((string)($req->get_param('order') ?: 'desc'));
        if ($order !== 'asc' && $order !== 'desc') {
            $order = 'desc';
        }

        Utils::log_debug('File list requested', [
            'user' => $base['username'],
            'page' => $page,
            'per_page' => $per_page,
            'order' => $order
        ]);

        if (!is_dir($dir)) {
            Utils::log_debug('User directory does not exist yet', [
                'user' => $base['username'],
                'dir' => $dir
            ]);

            return new \WP_REST_Response([
                'ok'          => true,
                'items'       => [],
                'owner'       => $base['username'],
                'count'       => 0,
                'page'        => $page,
                'per_page'    => $per_page,
                'total'       => 0,
                'total_pages' => 0,
                'order'       => $order,
            ]);
        }

        $items = [];
        $dh = @opendir($dir);
        if ($dh) {
            while (false !== ($entry = readdir($dh))) {
                if ($entry === '.' || $entry === '..' || $entry === 'index.html' || strpos($entry, "\0") !== false) {
                    continue;
                }

                // Skip metadata files using Utils helper
                if (Utils::is_metadata_file($entry)) {
                    continue;
                }
                if (Utils::is_system_file($entry)) {
                    continue;
                }

                $abs = $dir . DIRECTORY_SEPARATOR . $entry;
                if (\is_link($abs) || !is_file($abs)) {
                    continue;
                }

                $size  = @filesize($abs);
                $mtime = @filemtime($abs);
                $ft    = \wp_check_filetype($entry);
                $mime  = $ft && isset($ft['type']) ? $ft['type'] : null;

                $items[] = [
                    'name'     => $entry,
                    'url'      => $url . '/' . rawurlencode($entry),
                    'size'     => is_int($size) ? $size : null,
                    'mime'     => $mime,
                    'modified' => is_int($mtime) ? $mtime : null,
                ];
            }
            closedir($dh);
        }

        // Sort by mtime asc/desc; null goes last
        usort($items, function ($a, $b) use ($order) {
            $am = $a['modified'] ?? 0;
            $bm = $b['modified'] ?? 0;
            if ($am === $bm) return 0;
            return ($order === 'asc')
                ? (($am < $bm) ? -1 : 1)
                : (($am > $bm) ? -1 : 1);
        });

        $total = count($items);
        $total_pages = (int) ceil($total / $per_page);
        if ($page > $total_pages && $total_pages > 0) {
            $page = $total_pages;
        }
        $offset = ($page - 1) * $per_page;
        $paged_items = array_slice($items, $offset, $per_page);

        Utils::log_info('File list retrieved', [
            'user' => $base['username'],
            'total_files' => $total,
            'page' => $page,
            'returned' => count($paged_items)
        ]);

        $resp = new \WP_REST_Response([
            'ok'          => true,
            'items'       => $paged_items,
            'owner'       => $base['username'],
            'count'       => $total,
            'page'        => $page,
            'per_page'    => $per_page,
            'total'       => $total,
            'total_pages' => $total_pages,
            'order'       => $order,
        ]);

        // Optional: pagination-like headers
        $resp->header('X-Total-Count', (string)$total);
        $resp->header('X-Total-Pages', (string)$total_pages);

        return $resp;
    }

    /**
     * DELETE /files/{filename} - Delete a file in the user's folder
     *
     * @param \WP_REST_Request $req Current request
     * @return \WP_REST_Response Deletion result
     */
    public static function route_delete_file(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = \wp_get_current_user();
        if (!$user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Not authenticated'], 401);
        }

        $param = $req->get_param('filename');
        $base  = self::sanitize_user_filename($param);

        if (is_wp_error($base)) {
            Utils::log_warning('Delete rejected: invalid filename', [
                'user' => $user->user_login,
                'filename' => $param,
                'error' => $base->get_error_message()
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => $base->get_error_message()], 400);
        }

        $paths = self::get_user_base($user);
        $abs   = $paths['path'] . DIRECTORY_SEPARATOR . $base;

        if (!Utils::is_path_within_base($paths['path'], $abs)) {
            Utils::log_error('Delete rejected: path traversal attempt', [
                'user' => $paths['username'],
                'filename' => $param,
                'attempted_path' => $abs
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => __('Invalid file path', self::TEXT_DOMAIN)], 400);
        }

        // Verify it's a file inside the user's folder
        if (!file_exists($abs) || !is_file($abs)) {
            Utils::log_warning('Delete failed: file not found', [
                'user' => $paths['username'],
                'filename' => $base
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => __('File not found', self::TEXT_DOMAIN)], 404);
        }

        if (\is_link($abs)) {
            Utils::log_error('Delete rejected: symbolic link', [
                'user' => $paths['username'],
                'filename' => $base
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => __('Symbolic links not allowed', self::TEXT_DOMAIN)], 400);
        }

        // Get file size before deletion for logging
        $file_size = @filesize($abs);

        // Delete metadata file if exists
        $meta_file = $abs . '.meta.json';
        if (file_exists($meta_file)) {
            $meta_deleted = unlink($meta_file);
            Utils::log_debug('Metadata file deletion', [
                'user' => $paths['username'],
                'meta_file' => basename($meta_file),
                'success' => $meta_deleted
            ]);
        }

        // Delete the file
        $ok = unlink($abs);

        if (!$ok) {
            Utils::log_error('Delete failed: unable to remove file', [
                'user' => $paths['username'],
                'filename' => $base,
                'path' => $abs
            ]);

            return new \WP_REST_Response(['ok' => false, 'error' => __('Unable to delete file', self::TEXT_DOMAIN)], 500);
        }

        Utils::log_info('File deleted successfully', [
            'user' => $paths['username'],
            'filename' => $base
        ]);

        return new \WP_REST_Response([
            'ok'      => true,
            'deleted' => $base,
            'owner'   => $paths['username'],
        ]);
    }

    /**
     * HEAD /files/{filename} - Return metadata via headers, no body
     *
     * @param \WP_REST_Request $req Current request
     * @return \WP_REST_Response Response with metadata in headers
     */
    public static function route_head_file(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = \wp_get_current_user();
        if (!$user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => __('Not authenticated', self::TEXT_DOMAIN)], 401);
        }

        $param = $req->get_param('filename');
        $base  = self::sanitize_user_filename($param);

        if (\is_wp_error($base)) {
            return new \WP_REST_Response(['ok' => false, 'error' => $base->get_error_message()], 400);
        }

        $paths = self::get_user_base($user);
        $abs   = $paths['path'] . DIRECTORY_SEPARATOR . $base;

        if (!Utils::is_path_within_base($paths['path'], $abs)) {
            return new \WP_REST_Response(['ok' => false, 'error' => __('Invalid file path', self::TEXT_DOMAIN)], 400);
        }

        if (!\file_exists($abs) || !\is_file($abs)) {
            return new \WP_REST_Response(['ok' => false, 'error' => __('File not found', self::TEXT_DOMAIN)], 404);
        }

        // Get metadata
        $size  = @\filesize($abs);
        $mtime = @\filemtime($abs);
        $ft    = \wp_check_filetype($base);
        $mime  = ($ft && isset($ft['type'])) ? $ft['type'] : 'application/octet-stream';

        // Simple ETag based on user path + size + mtime
        $etag = '"' . \md5($paths['username'] . '/' . $base . ':' . (int)$size . ':' . (int)$mtime) . '"';

        Utils::log_debug('File metadata requested', [
            'user' => $paths['username'],
            'filename' => $base,
            'size' => $size,
            'mime' => $mime
        ]);

        // Response without body: metadata in headers
        $resp = new \WP_REST_Response(null, 200);
        $resp->header('Content-Length', '0');
        $resp->header('Cache-Control', 'private, max-age=60');
        if (\is_int($mtime)) {
            $resp->header('Last-Modified', \gmdate('D, d M Y H:i:s', $mtime) . ' GMT');
        }
        $resp->header('ETag', $etag);

        // Custom convenience headers for the client
        if (\is_int($size)) {
            $resp->header('X-PFU-Size', (string)$size);
        }
        $resp->header('X-PFU-Mime', $mime);
        $resp->header('X-PFU-Name', $base);
        $resp->header('X-PFU-Owner', $paths['username']);

        return $resp;
    }

    /**
     * Create an empty index.html file in the directory to prevent directory listing (if enabled on server)
     *
     * @param string $dir Directory path
     */
    private static function ensure_index_html(string $dir): void
    {
        $index = trailingslashit($dir) . 'index.html';
        if (file_exists($index)) {
            return;
        }

        $result = @file_put_contents($index, "<!-- silence is golden -->");

        if ($result === false) {
            Utils::log_warning('Failed to create index.html', ['dir' => $dir]);
        }
    }

    /**
     * Get the user's base directory info
     *
     * @param \WP_User $user User object
     * @return array Array with 'path', 'url', and 'username' keys
     */
    public static function get_user_base(\WP_User $user): array
    {
        $username = \sanitize_user($user->user_login, true);
        if (empty($username)) {
            $username = 'user-' . $user->ID;
        }
        $subdir = '/' . self::SUB_BASE . '/' . $username;

        // Use wp_upload_dir() without filters to get standard basedir/baseurl
        $uploads = \wp_upload_dir();
        $basedir = isset($uploads['basedir']) ? $uploads['basedir'] : \WP_CONTENT_DIR . '/uploads';
        $baseurl = isset($uploads['baseurl']) ? $uploads['baseurl'] : \content_url('/uploads');

        $path = $basedir . $subdir;
        $url  = $baseurl . $subdir;

        // Ensure the directory exists (don't fail if it doesn't)
        if (\wp_mkdir_p($path)) {
            self::ensure_index_html($path);
        }

        return ['path' => $path, 'url' => $url, 'username' => $username];
    }

    /**
     * Strong filename validation (no path traversal, no slashes)
     *
     * @param mixed $filename Input filename
     * @return string|\WP_Error Sanitized basename or WP_Error
     */
    public static function sanitize_user_filename($filename)
    {
        if (!is_string($filename) || $filename === '') {
            return new \WP_Error('pfu_bad_filename', 'Invalid filename');
        }

        // Use Utils sanitization
        $base = Utils::sanitize_filename($filename);

        // Additional validation
        if ($base === '' || $base === '.' || $base === '..' || strpos($base, "\0") !== false) {
            return new \WP_Error('pfu_bad_filename', 'Invalid filename');
        }

        if (strlen($base) > 255) {
            return new \WP_Error('pfu_bad_filename', 'Filename too long');
        }

        return $base;
    }

    private static function check_rate_limit(int $user_id): bool
    {
        $transient_key = "pfu:v1:rate:" . $user_id;
        $attempts = get_transient($transient_key) ?: 0;

        if ($attempts >= 50) { // 50 upload/ora
            return false;
        }

        set_transient($transient_key, $attempts + 1, HOUR_IN_SECONDS);
        return true;
    }
}
