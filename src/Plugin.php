<?php

namespace PFU;

if (! defined('ABSPATH')) {
    exit;
}

class Plugin
{

    const REST_NS   = 'fileuploader/v1';
    const SLUG      = 'private-file-uploader';
    const SUB_BASE  = 'media/private-file-uploader'; // sotto uploads/

    public static function init(): void
    {
        add_action('rest_api_init', [__CLASS__, 'register_routes']);
    }

    public static function register_routes(): void
    {
        register_rest_route(self::REST_NS, '/ping', [
            [
                'methods'  => 'GET',
                'callback' => [__CLASS__, 'route_ping'],
                'permission_callback' => [__CLASS__, 'require_auth'],
            ],
        ]);

        register_rest_route(self::REST_NS, '/upload', [
            [
                'methods'  => 'POST',
                'callback' => [__CLASS__, 'route_upload'],
                'permission_callback' => [__CLASS__, 'require_can_upload'],
            ],
        ]);
    }

    /** Permette solo richieste autenticate (App Password) */
    public static function require_auth(\WP_REST_Request $req)
    {
        if (is_user_logged_in()) {
            return true;
        }
        return new \WP_Error('pfu_auth', 'Authentication required', ['status' => 401]);
    }

    /** Richiede utente autenticato con capacità di upload */
    public static function require_can_upload(\WP_REST_Request $req)
    {
        if (is_user_logged_in() && current_user_can('upload_files')) {
            return true;
        }
        return new \WP_Error('pfu_forbidden', 'Insufficient permissions', ['status' => 403]);
    }

    /** GET /ping — utile per testare credenziali via curl */
    public static function route_ping(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = wp_get_current_user();
        return new \WP_REST_Response([
            'ok'      => true,
            'user'    => $user ? $user->user_login : null,
            'message' => 'Hello from Private File Uploader',
        ]);
    }

    /**
     * POST /upload — upload di UN file (campo multipart "file") verso uploads/media/private-file-uploader/<username>/
     * Usa upload_dir filter (scoped) e wp_handle_sideload per muovere il file.
     */
    public static function route_upload(\WP_REST_Request $req): \WP_REST_Response
    {
        // Leggi i file della richiesta (WP li mappa da $_FILES)
        $files = $req->get_file_params();

        // Campo atteso: "file" (come in curl -F 'file=@...')
        if (empty($files['file']) || ! is_array($files['file'])) {
            // fallback: primo file qualunque, se presente
            if (is_array($files) && ! empty($files)) {
                $first = reset($files);
                if (is_array($first)) {
                    $files['file'] = $first;
                }
            }
        }

        if (empty($files['file']) || ! is_array($files['file'])) {
            return new \WP_REST_Response(
                ['ok' => false, 'error' => 'No file provided (multipart field "file")'],
                400
            );
        }

        $user = wp_get_current_user();
        if (! $user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Not authenticated'], 401);
        }

        // ... il resto della funzione rimane uguale, ma usa $files['file'] al posto di $_FILES['file']:
        $username = sanitize_user($user->user_login, true);
        if (empty($username)) {
            $username = 'user-' . $user->ID;
        }
        $subdir = '/' . self::SUB_BASE . '/' . $username;

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
        // Assicuriamoci che le funzioni upload siano caricate
        if (! function_exists('\wp_handle_sideload')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        $moved = \wp_handle_sideload($file_array, $overrides);
        remove_filter('upload_dir', $filter, 10);

        if (isset($moved['error'])) {
            return new \WP_REST_Response(['ok' => false, 'error' => $moved['error']], 400);
        }

        return new \WP_REST_Response([
            'ok'       => true,
            'file'     => wp_basename($moved['file']),
            'path'     => $moved['file'],
            'url'      => $moved['url'],
            'mime'     => $moved['type'],
            'owner'    => $username,
            'location' => self::SUB_BASE . '/' . $username,
        ], 201);
    }

    /** Crea un index.html vuoto nella cartella per evitare directory listing (se attivo sul server) */
    private static function ensure_index_html(string $dir): void
    {
        $index = trailingslashit($dir) . 'index.html';
        if (file_exists($index)) {
            return;
        }
        @file_put_contents($index, "<!-- silence is golden -->");
    }
}
