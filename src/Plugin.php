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

    // Valori di default; sovrascrivibili via filter (vedi sotto)
    const DEFAULT_MAX_UPLOAD_BYTES = 50 * 1024 * 1024; // 50 MB
    const DEFAULT_ALLOWED_MIME = [
        'application/zip',
        'image/jpeg',
        'image/png',
        'application/pdf',
    ];

    public static function storage_root_base(): string
    {
        $up = \wp_get_upload_dir();
        return trailingslashit($up['basedir']) . self::SUB_BASE; // e.g. wp-content/uploads/media/private-file-uploader
    }

    // Restituisce il limite effettivo (defaults → options → filters)
    public static function effective_max_upload_bytes(): int
    {
        return self::get_max_upload_bytes();
    }

    /** @return array<string> Elenco MIME effettivi (defaults → options → filters) */
    public static function effective_allowed_mime_types(): array
    {
        return self::get_allowed_mime_types();
    }

    // Recupera il limite massimo (byte) – configurabile con filtro 'pfu_max_upload_bytes'
    private static function get_max_upload_bytes(): int
    {
        // 1) defaults
        $max = self::DEFAULT_MAX_UPLOAD_BYTES;

        // 2) options (admin)
        if (class_exists(__NAMESPACE__ . '\\Admin')) {
            $opt = Admin::get_settings();
            if (! empty($opt['max_upload_bytes']) && (int)$opt['max_upload_bytes'] > 0) {
                $max = (int)$opt['max_upload_bytes'];
            }
        }

        // 3) filters (possono ancora override)
        $max = (int) apply_filters('pfu_max_upload_bytes', $max);
        return $max > 0 ? $max : self::DEFAULT_MAX_UPLOAD_BYTES;
    }

    // Recupera allowlist MIME – configurabile con filtro 'pfu_allowed_mime_types'
    /** @return array<string> */
    private static function get_allowed_mime_types(): array
    {
        // 1) defaults
        $allowed = self::DEFAULT_ALLOWED_MIME;

        // 2) options (admin)
        if (class_exists(__NAMESPACE__ . '\\Admin')) {
            $opt = Admin::get_settings();
            if (! empty($opt['allowed_mime_types']) && is_array($opt['allowed_mime_types'])) {
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

    private static function human_bytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        $n = $bytes;
        while ($n >= 1024 && $i < count($units) - 1) {
            $n /= 1024;
            $i++;
        }
        return sprintf('%s %s', ($i === 0 ? (string)$n : number_format($n, 2)), $units[$i]);
    }

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

        // GET /files  - lista dei file dell’utente
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
                    ],
                    'per_page' => [
                        'description' => 'Items per page (1..1000)',
                        'type'        => 'integer',
                        'required'    => false,
                    ],
                    'order' => [
                        'description' => 'Sort by modified time: desc|asc',
                        'type'        => 'string',
                        'required'    => false,
                    ],
                ],
            ],
        ]);

        // DELETE /files/{filename} - cancella un file dell’utente
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

        // HEAD /files/{filename} - metadata veloci via header (no body)
        register_rest_route(self::REST_NS, '/files/(?P<filename>[^/]+)', [
            [
                'methods'  => 'HEAD',
                'callback' => [__CLASS__, 'route_head_file'],
                'permission_callback' => [__CLASS__, 'require_auth'],
                'args' => [
                    'filename' => [
                        'description' => 'Base filename to inspect (no slashes)',
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

        // ---- Validazioni: max size + MIME allowlist ----
        $size = isset($files['file']['size']) ? (int)$files['file']['size'] : 0;
        $max  = self::get_max_upload_bytes();
        if ($size <= 0) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Empty upload or unknown size'], 400);
        }
        if ($size > $max) {
            return new \WP_REST_Response([
                'ok'    => false,
                'error' => 'File too large',
                'limit' => $max,
                'limitHuman' => self::human_bytes($max),
                'got'   => $size,
                'gotHuman' => self::human_bytes($size),
            ], 413); // Payload Too Large
        }

        // MIME detection: contenuto (finfo) → fallback su estensione → fallback header
        $allowed = self::get_allowed_mime_types();
        $mime = null;

        // 1) dal contenuto
        if (function_exists('finfo_open') && is_readable($files['file']['tmp_name'])) {
            $f = finfo_open(FILEINFO_MIME_TYPE);
            if ($f) {
                $mime = finfo_file($f, $files['file']['tmp_name']) ?: null;
                finfo_close($f);
            }
        }
        // 2) dall’estensione
        if ($mime === null) {
            $ft = \wp_check_filetype((string)$files['file']['name']);
            if ($ft && !empty($ft['type'])) {
                $mime = $ft['type'];
            }
        }
        // 3) dall’header del client (meno affidabile)
        if ($mime === null && !empty($files['file']['type'])) {
            $mime = (string)$files['file']['type'];
        }

        if ($mime === null || !in_array($mime, $allowed, true)) {
            return new \WP_REST_Response([
                'ok'        => false,
                'error'     => 'Unsupported media type',
                'mime'      => $mime,
                'allowed'   => $allowed,
                'hint'      => 'Allowed MIME types can be configured via the pfu_allowed_mime_types filter.',
            ], 415); // Unsupported Media Type
        }

        $user = wp_get_current_user();
        if (! $user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Not authenticated'], 401);
        }

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

        // Parametri
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

        if (! is_dir($dir)) {
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
                $abs = $dir . DIRECTORY_SEPARATOR . $entry;
                if (\is_link($abs)) {
                    continue;
                } // no symlink
                if (! is_file($abs)) {
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
                    'modified' => is_int($mtime) ? $mtime : null, // timestamp
                ];
            }
            closedir($dh);
        }

        // Ordina per mtime asc/desc; null va in coda
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

        /* Converti modified in ISO8601 per output
        foreach ($paged_items as &$it) {
           $it['modified'] = is_int($it['modified']) ? gmdate('c', $it['modified']) : null;
        }*/

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

        // (facoltativo) intestazioni pagination-like
        $resp->header('X-Total-Count', (string)$total);
        $resp->header('X-Total-Pages', (string)$total_pages);

        return $resp;
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

        if (! self::path_within_base($paths['path'], $abs)) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Invalid file path'], 400);
        }

        // Verifica che sia un file dentro la cartella dell’utente
        if (! file_exists($abs) || ! is_file($abs)) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'File not found'], 404);
        }

        if (\is_link($abs)) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Symbolic links not allowed'], 400);
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

    /** HEAD /files/{filename} — ritorna metadata via header, nessun body */
    public static function route_head_file(\WP_REST_Request $req): \WP_REST_Response
    {
        $user = \wp_get_current_user();
        if (! $user || 0 === $user->ID) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Not authenticated'], 401);
        }

        $param = $req->get_param('filename');
        $base  = self::sanitize_user_filename($param);
        if (\is_wp_error($base)) {
            return new \WP_REST_Response(['ok' => false, 'error' => $base->get_error_message()], 400);
        }

        $paths = self::get_user_base($user);
        $abs   = $paths['path'] . DIRECTORY_SEPARATOR . $base;

        if (! self::path_within_base($paths['path'], $abs)) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'Invalid file path'], 400);
        }

        if (! \file_exists($abs) || ! \is_file($abs)) {
            return new \WP_REST_Response(['ok' => false, 'error' => 'File not found'], 404);
        }

        // Metadata
        $size  = @\filesize($abs);
        $mtime = @\filemtime($abs);
        $ft    = \wp_check_filetype($base);
        $mime  = ($ft && isset($ft['type'])) ? $ft['type'] : 'application/octet-stream';

        // ETag semplice basata su path utente + size + mtime
        $etag = '"' . \md5($paths['username'] . '/' . $base . ':' . (int)$size . ':' . (int)$mtime) . '"';

        // Risposta senza corpo: metadati nei header
        $resp = new \WP_REST_Response(null, 200);
        $resp->header('Content-Length', '0');
        $resp->header('Cache-Control', 'private, max-age=60');
        if (\is_int($mtime)) {
            $resp->header('Last-Modified', \gmdate('D, d M Y H:i:s', $mtime) . ' GMT');
        }
        $resp->header('ETag', $etag);

        // Header custom “comodi” per il client
        if (\is_int($size)) {
            $resp->header('X-PFU-Size', (string)$size);
        }
        $resp->header('X-PFU-Mime', $mime);
        $resp->header('X-PFU-Name', $base);
        $resp->header('X-PFU-Owner', $paths['username']);

        return $resp;
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
    public static function get_user_base(\WP_User $user): array
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
    public static function sanitize_user_filename($filename)
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

    //Helper: Aggiungiamo una verifica con realpath() 
    //per assicurarci che il path target cada davvero dentro alla cartella utente (protezione extra contro symlink/traversal)
    /** TRUE se $candidate è dentro $base (dopo realpath), altrimenti FALSE */
    public static function path_within_base(string $base, string $candidate): bool
    {
        $baseReal = \realpath($base);
        $candReal = \realpath($candidate);
        if ($baseReal === false || $candReal === false) {
            return false;
        }
        $baseReal = rtrim($baseReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        return strncmp($candReal, $baseReal, strlen($baseReal)) === 0;
    }
}
