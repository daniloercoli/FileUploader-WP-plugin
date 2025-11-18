<?php

namespace PFU;

if (!defined('ABSPATH')) {
    exit;
}

class Utils
{
    /**
     * Log a message to the debug log (only if WP_DEBUG is enabled)
     *
     * @param string $message Message to log
     * @param string $level Log level: info, warning, error, debug
     * @param array $context Additional context data
     */
    public static function log(string $message, string $level = 'info', array $context = []): void
    {
        if (!defined('WP_DEBUG') || !WP_DEBUG || !defined('WP_DEBUG_LOG') || !WP_DEBUG_LOG) {
            return;
        }

        $level = strtoupper($level);
        $timestamp = current_time('Y-m-d H:i:s');
        $user_id = get_current_user_id();
        $user_info = $user_id ? "user:{$user_id}" : 'guest';

        $log_message = sprintf(
            '[%s] [PFU-%s] [%s] %s',
            $timestamp,
            $level,
            $user_info,
            $message
        );

        if (!empty($context)) {
            $log_message .= ' | Context: ' . json_encode($context);
        }

        error_log($log_message);
    }

    /**
     * Log info message
     *
     * @param string $message Message to log
     * @param array $context Additional context
     */
    public static function log_info(string $message, array $context = []): void
    {
        self::log($message, 'info', $context);
    }

    /**
     * Log warning message
     *
     * @param string $message Message to log
     * @param array $context Additional context
     */
    public static function log_warning(string $message, array $context = []): void
    {
        self::log($message, 'warning', $context);
    }

    /**
     * Log error message
     *
     * @param string $message Message to log
     * @param array $context Additional context
     */
    public static function log_error(string $message, array $context = []): void
    {
        self::log($message, 'error', $context);
    }

    /**
     * Log debug message
     *
     * @param string $message Message to log
     * @param array $context Additional context
     */
    public static function log_debug(string $message, array $context = []): void
    {
        self::log($message, 'debug', $context);
    }

    /**
     * Convert bytes to human-readable format
     *
     * @param int $bytes Number of bytes
     * @param int $precision Decimal precision
     * @return string Human-readable size
     */
    public static function human_bytes(int $bytes, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        $i = 0;
        $n = $bytes;

        while ($n >= 1024 && $i < count($units) - 1) {
            $n /= 1024;
            $i++;
        }

        if ($i === 0) {
            return "{$n} {$units[$i]}";
        }

        return number_format($n, $precision) . " {$units[$i]}";
    }

    /**
     * Convert shorthand INI notation (e.g. "128M", "2G") to bytes
     *
     * @param mixed $val INI value
     * @return int Bytes
     */
    public static function ini_to_bytes($val): int
    {
        if ($val === null || $val === '') {
            return 0;
        }

        $v = trim((string)$val);

        if ($v === '-1') {
            return PHP_INT_MAX; // unlimited
        }

        if (preg_match('/^\d+$/', $v)) {
            return (int)$v;
        }

        if (!preg_match('/^\s*([0-9\.]+)\s*([KMGkmg])\s*$/i', $v, $m)) {
            return (int)$v;
        }

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
    public static function get_ini_pair(string $key): array
    {
        $raw = @ini_get($key);
        $bytes = self::ini_to_bytes($raw);

        if ($raw === false || $raw === '') {
            $human = 'N/A';
        } elseif ($raw === '-1') {
            $human = __('Unlimited', 'pfu');
        } else {
            $human = self::human_bytes($bytes);
        }

        return [$human, $bytes, (string)$raw];
    }

    /**
     * Sanitize filename with more robust character handling
     *
     * @param string $filename Original filename
     * @return string Sanitized filename
     */
    public static function sanitize_filename(string $filename): string
    {
        // Remove path separators
        $base = wp_basename($filename);

        // Transliterate unicode characters
        $base = remove_accents($base);

        // Replace spaces with underscores
        $base = str_replace(' ', '_', $base);

        // Remove dangerous characters, keep only alphanumeric, dots, underscores, hyphens
        $base = preg_replace('/[^A-Za-z0-9._-]/', '', $base);

        // Limit length
        if (strlen($base) > 255) {
            $info = pathinfo($base);
            $name = substr($info['filename'], 0, 200);
            $ext = isset($info['extension']) ? '.' . $info['extension'] : '';
            $base = $name . $ext;
        }

        return $base;
    }

    /**
     * Get unique filename to avoid overwriting existing files
     *
     * @param string $dir Directory path
     * @param string $filename Desired filename
     * @return string Unique filename
     */
    public static function get_unique_filename(string $dir, string $filename): string
    {
        $path = trailingslashit($dir) . $filename;

        if (!file_exists($path)) {
            return $filename;
        }

        $info = pathinfo($filename);
        $name = $info['filename'];
        $ext = isset($info['extension']) ? '.' . $info['extension'] : '';
        $counter = 1;

        while (file_exists(trailingslashit($dir) . "{$name}_{$counter}{$ext}")) {
            $counter++;
            if ($counter > 9999) {
                // Safety limit reached, use unique ID
                return $name . '_' . uniqid() . $ext;
            }
        }

        return "{$name}_{$counter}{$ext}";
    }

    /**
     * Calculate total size of a directory
     *
     * @param string $dir Directory path
     * @return int Total size in bytes
     */
    public static function get_directory_size(string $dir): int
    {
        if (!is_dir($dir)) {
            return 0;
        }

        $total = 0;

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file) {
                if ($file->isFile() && !$file->isLink()) {
                    $total += $file->getSize();
                }
            }
        } catch (\Exception $e) {
            self::log_error('Error calculating directory size', [
                'dir' => $dir,
                'error' => $e->getMessage()
            ]);
        }

        return $total;
    }

    /**
     * Count files in a directory
     *
     * @param string $dir Directory path
     * @param bool $recursive Count recursively
     * @return int Number of files
     */
    public static function count_directory_files(string $dir, bool $recursive = false): int
    {
        if (!is_dir($dir)) {
            return 0;
        }

        $count = 0;

        try {
            if ($recursive) {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::LEAVES_ONLY
                );
            } else {
                $iterator = new \DirectoryIterator($dir);
            }

            foreach ($iterator as $file) {
                if ($file->isFile() && !$file->isLink()) {
                    $count++;
                }
            }
        } catch (\Exception $e) {
            self::log_error('Error counting directory files', [
                'dir' => $dir,
                'error' => $e->getMessage()
            ]);
        }

        return $count;
    }

    /**
     * Check if file extension is allowed
     *
     * @param string $filename Filename to check
     * @param array $allowed_extensions List of allowed extensions
     * @return bool True if allowed
     */
    public static function is_extension_allowed(string $filename, array $allowed_extensions): bool
    {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        return in_array($ext, array_map('strtolower', $allowed_extensions), true);
    }

    /**
     * Validate file MIME type using multiple methods
     *
     * @param string $filepath Path to file
     * @param string $filename Original filename
     * @return string|null Detected MIME type or null
     */
    public static function detect_mime_type(string $filepath, string $filename = ''): ?string
    {
        $mime = null;

        // Method 1: Using finfo (most reliable)
        if (function_exists('finfo_open') && is_readable($filepath)) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo) {
                $detected = finfo_file($finfo, $filepath);
                if ($detected !== false) {
                    $mime = $detected;
                }
                finfo_close($finfo);
            }
        }

        // Method 2: Using file extension as fallback
        if ($mime === null && !empty($filename)) {
            $filetype = wp_check_filetype($filename);
            if ($filetype && !empty($filetype['type'])) {
                $mime = $filetype['type'];
            }
        }

        // Method 3: Using mime_content_type (if available)
        if ($mime === null && function_exists('mime_content_type')) {
            $detected = @mime_content_type($filepath);
            if ($detected !== false) {
                $mime = $detected;
            }
        }

        return $mime;
    }

    /**
     * Check if a filename is a metadata file
     *
     * @param string $filename Filename to check
     * @return bool True if it's a metadata file
     */
    public static function is_metadata_file(string $filename): bool
    {
        return strlen($filename) > 10 && substr($filename, -10) === '.meta.json';
    }

    public static function is_system_file(string $filename): bool
    {
        $system_files = ['.DS_Store', 'Thumbs.db', 'desktop.ini', '._.DS_Store'];
        return in_array($filename, $system_files, true);
    }

    /** true se il filename è una thumbnail generata (-pfu-thumb prima dell'estensione) */
    public static function is_thumb_filename(string $filename): bool
    {
        // foto.jpg => foto-pfu-thumb.jpg
        $dot = strrpos($filename, '.');
        if ($dot === false) {
            return str_ends_with($filename, '-pfu-thumb');
        }
        $name = substr($filename, 0, $dot);
        return str_ends_with($name, '-pfu-thumb');
    }

    /**
     * Get metadata filename for a given file
     *
     * @param string $filepath Path to the file
     * @return string Metadata file path
     */
    public static function get_metadata_filepath(string $filepath): string
    {
        return $filepath . '.meta.json';
    }

    /**
     * Delete file and its metadata
     *
     * @param string $filepath Path to the file
     * @return bool True if file was deleted successfully
     */
    public static function delete_file_with_metadata(string $filepath): bool
    {
        $meta_file = self::get_metadata_filepath($filepath);

        // Delete metadata first
        if (file_exists($meta_file)) {
            @unlink($meta_file);
        }

        // Delete the actual file
        return @unlink($filepath);
    }

    /**
     * Save metadata for an uploaded file
     *
     * @param string $filepath Path to the file
     * @param array $metadata Metadata to save
     * @return bool True on success
     */
    public static function save_file_metadata(string $filepath, array $metadata): bool
    {
        $meta_file = $filepath . '.meta.json';

        $data = array_merge([
            'uploaded_at' => current_time('mysql'),
            'user_id' => get_current_user_id(),
            'plugin_version' => '0.1.0',
        ], $metadata);

        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            self::log_error('Failed to encode metadata to JSON', ['filepath' => $filepath]);
            return false;
        }

        $result = @file_put_contents($meta_file, $json);

        if ($result === false) {
            self::log_error('Failed to write metadata file', ['meta_file' => $meta_file]);
            return false;
        }

        return true;
    }

    /**
     * Load metadata for a file
     *
     * @param string $filepath Path to the file
     * @return array|null Metadata or null if not found
     */
    public static function load_file_metadata(string $filepath): ?array
    {
        $meta_file = $filepath . '.meta.json';

        if (!file_exists($meta_file)) {
            return null;
        }

        $json = @file_get_contents($meta_file);

        if ($json === false) {
            return null;
        }

        $data = json_decode($json, true);

        if (!is_array($data)) {
            return null;
        }

        return $data;
    }

    /**
     * Recursively delete a directory
     *
     * @param string $dir Directory path
     * @return bool True on success
     */
    public static function recursive_rmdir(string $dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }

        $items = @scandir($dir);

        if (!is_array($items)) {
            return false;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $path = $dir . DIRECTORY_SEPARATOR . $item;

            if (is_link($path)) {
                @unlink($path);
                continue;
            }

            if (is_dir($path)) {
                self::recursive_rmdir($path);
                continue;
            }

            @unlink($path);
        }

        return @rmdir($dir);
    }

    /**
     * Get client IP address
     *
     * @return string IP address
     */
    public static function get_client_ip(): string
    {
        $ip_keys = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];

        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                // Handle comma-separated IPs (proxies)
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }

    /**
     * Get user agent string
     *
     * @return string User agent
     */
    public static function get_user_agent(): string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    }

    /**
     * Check if request is from mobile device
     *
     * @return bool True if mobile
     */
    public static function is_mobile_request(): bool
    {
        $user_agent = self::get_user_agent();

        $mobile_agents = [
            'Android',
            'iPhone',
            'iPad',
            'iPod',
            'BlackBerry',
            'Windows Phone',
            'Mobile',
            'Tablet'
        ];

        foreach ($mobile_agents as $agent) {
            if (stripos($user_agent, $agent) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generate a secure random token
     *
     * @param int $length Token length
     * @return string Random token
     */
    public static function generate_token(int $length = 32): string
    {
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes($length / 2));
        }

        return wp_generate_password($length, false);
    }

    /**
     * Verify that a path is within a base directory (security check)
     *
     * @param string $base Base directory
     * @param string $candidate Candidate path
     * @return bool True if safe
     */
    public static function is_path_within_base(string $base, string $candidate): bool
    {
        $base_real = realpath($base);
        $cand_real = realpath($candidate);

        if ($base_real === false || $cand_real === false) {
            return false;
        }

        $base_real = rtrim($base_real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

        return strncmp($cand_real, $base_real, strlen($base_real)) === 0;
    }

    /**
     * Format timestamp as relative time (e.g., "2 hours ago")
     *
     * @param int $timestamp Unix timestamp
     * @return string Relative time string
     */
    public static function time_ago(int $timestamp): string
    {
        $diff = time() - $timestamp;

        if ($diff < 60) {
            return sprintf(_n('%s second ago', '%s seconds ago', $diff, 'pfu'), $diff);
        }

        $diff = round($diff / 60);
        if ($diff < 60) {
            return sprintf(_n('%s minute ago', '%s minutes ago', $diff, 'pfu'), $diff);
        }

        $diff = round($diff / 60);
        if ($diff < 24) {
            return sprintf(_n('%s hour ago', '%s hours ago', $diff, 'pfu'), $diff);
        }

        $diff = round($diff / 24);
        if ($diff < 30) {
            return sprintf(_n('%s day ago', '%s days ago', $diff, 'pfu'), $diff);
        }

        $diff = round($diff / 30);
        if ($diff < 12) {
            return sprintf(_n('%s month ago', '%s months ago', $diff, 'pfu'), $diff);
        }

        $diff = round($diff / 12);
        return sprintf(_n('%s year ago', '%s years ago', $diff, 'pfu'), $diff);
    }
}
