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

        // GET /files  → lista dei file dell’utente
        register_rest_route(self::REST_NS, '/files', [
            [
                'methods'  => 'GET',
                'callback' => [__CLASS__, 'route_list_files'],
                'permission_callback' => [__CLASS__, 'require_auth'],
                'args' => [
                    // opzionale: ?page=1&per_page=100 in futuro; per ora restituiamo tutto
                ],
            ],
        ]);

        // DELETE /files/{filename} → cancella un file dell’utente
        register_rest_route(self::REST_NS, '/files/(?P<filename>[^/]+)', [
            [
                'methods'  => 'DELETE',
                'callback' => [__CLASS__, 'route_delete_file'],
                'permission_callback' => [__CLASS__, 'require_can_upload'],
                'args' => [
                    'filename' => [
                        'description' => 'Base filename to delete (no slashes)',
                        'required' => true,
                    ],
                ],
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

    /** GET /files — lista file per l’utente corrente */
    public static function route_list_files(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = \wp_get_current_user();
        if (! $user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Not authenticated'], 401);
        }

        $base = self::get_user_base($user);
        $dir  = $base['path'];
        $url  = $base['url'];

        if (! is_dir($dir)) {
            // Nessun file ancora
            return new \WP_REST_Response(['ok' => true, 'items' => [], 'owner' => $base['username']]);
        }

        $items = [];
        $dh = @opendir($dir);
        if ($dh) {
            while (false !== ($entry = readdir($dh))) {
                // salta dotfiles e index.html
                if ($entry === '.' || $entry === '..' || $entry === 'index.html' || strpos($entry, "\0") !== false) {
                    continue;
                }
                $abs = $dir . DIRECTORY_SEPARATOR . $entry;
                if (is_file($abs)) {
                    $size = @filesize($abs);
                    $mtime = @filemtime($abs);
                    $ft = \wp_check_filetype($entry);
                    $mime = $ft && isset($ft['type']) ? $ft['type'] : null;

                    $items[] = [
                        'name' => $entry,
                        'url'  => $url . '/' . rawurlencode($entry),
                        'size' => is_int($size) ? $size : null,
                        'mime' => $mime,
                        'modified' => is_int($mtime) ? gmdate('c', $mtime) : null,
                    ];
                }
            }
            closedir($dh);
        }

        // Ordina per mtime desc (più recenti prima)
        usort($items, function ($a, $b) {
            return strcmp((string)$b['modified'], (string)$a['modified']);
        });

        return new \WP_REST_Response([
            'ok'    => true,
            'items' => $items,
            'owner' => $base['username'],
            'count' => count($items),
        ]);
    }

    /** DELETE /files/{filename} — cancella un file nella cartella dell’utente */
    public static function route_delete_file(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = \wp_get_current_user();
        if (! $user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Not authenticated'], 401);
        }

        $param = $req->get_param('filename');
        $base  = self::sanitize_user_filename($param);
        if (is_wp_error($base)) {
            return new \WP_REST_Response(['ok' => false, 'error' => $base->get_error_message()], 400);
        }

        $paths = self::get_user_base($user);
        $abs   = $paths['path'] . DIRECTORY_SEPARATOR . $base;

        // Verifica che sia un file dentro la cartella dell’utente
        if (! file_exists($abs) || ! is_file($abs)) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'File not found'], 404);
        }

        // Cancella
        $ok = @unlink($abs);
        if (! $ok) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Unable to delete file'], 500);
        }

        return new \WP_REST_Response([
            'ok'      => true,
            'deleted' => $base,
            'owner'   => $paths['username'],
        ]);
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

    /** Ritorna [ 'path' => <abs path>, 'url' => <base url> ] per la cartella dell'utente */
    private static function get_user_base(\WP_User $user): array
    {
        $username = \sanitize_user($user->user_login, true);
        if (empty($username)) {
            $username = 'user-' . $user->ID;
        }
        $subdir = '/' . self::SUB_BASE . '/' . $username;

        // Usa wp_upload_dir() senza filtri per ottenere basedir/baseurl standard
        $uploads = \wp_upload_dir();
        $basedir = isset($uploads['basedir']) ? $uploads['basedir'] : \WP_CONTENT_DIR . '/uploads';
        $baseurl = isset($uploads['baseurl']) ? $uploads['baseurl'] : \content_url('/uploads');

        $path = $basedir . $subdir;
        $url  = $baseurl . $subdir;

        // assicurati che la cartella esista (non fallire se manca)
        if (\wp_mkdir_p($path)) {
            self::ensure_index_html($path);
        }

        return ['path' => $path, 'url' => $url, 'username' => $username];
    }

    /** Validazione forte del filename (niente path traversal, niente slash). Restituisce basename sanificato o WP_Error */
    private static function sanitize_user_filename($filename)
    {
        if (! is_string($filename) || $filename === '') {
            return new \WP_Error('pfu_bad_filename', 'Invalid filename');
        }
        // Normalizza separatori e prendi solo il basename
        $base = \wp_basename(str_replace(['\\', '/'], DIRECTORY_SEPARATOR, $filename));
        // Vietiamo hidden files/dotfiles e path sospetti
        if ($base === '.' || $base === '..' || strpos($base, "\0") !== false) {
            return new \WP_Error('pfu_bad_filename', 'Invalid filename');
        }
        // Solo caratteri “sicuri” comuni; puoi allentare questa regex se necessario
        if (! preg_match('/^[A-Za-z0-9._ -]{1,255}$/', $base)) {
            return new \WP_Error('pfu_bad_filename', 'Filename contains invalid characters');
        }
        return $base;
    }
}
