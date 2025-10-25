# Private File Uploader (WordPress Plugin)

Custom REST endpoints to accept file uploads into **per-user directories**.  
Designed to pair with the **Private File Uploader** mobile app (React Native).  
Authentication uses **WordPress Application Passwords** over HTTPS.

> **Note:** This repository contains the **server component**.  
> The React Native client integrates with these endpoints.

---

## What it does

- Exposes REST endpoints under:  
  - `GET  /wp-json/fileuploader/v1/ping` - Authentication check
  - `POST /wp-json/fileuploader/v1/upload` - Upload files (multipart `file` field)
  - `GET  /wp-json/fileuploader/v1/files` - List user's files (with pagination)
  - `DELETE /wp-json/fileuploader/v1/files/{filename}` - Delete a file
  - `HEAD /wp-json/fileuploader/v1/files/{filename}` - Get file metadata
- Stores uploaded files under:  
  `wp-content/uploads/media/private-file-uploader/<username>/...`
- Scopes the upload directory **per-user** (prevents mixing user files)
- Leaves an `index.html` in each folder to discourage directory listing
- Provides an admin interface to manage files, settings, and user deletion options

---

## Requirements

- WordPress **5.6+** (Application Passwords introduced in core)
- PHP **8.0+** (tested with 8.1/8.2/8.3)
- HTTPS strongly recommended in production

---

## Installation

1. Copy this plugin folder into:  
   `wp-content/plugins/wp-private-file-uploader/`
2. In WP Admin → **Plugins**, activate **Private File Uploader**
3. Ensure the REST API is reachable:
   - Rewrite form (pretty): `https://example.com/wp-json/`  
   - Fallback form: `https://example.com/index.php?rest_route=/`
4. (Optional) If `/wp-json` returns 404 on local Apache, flush permalinks  
   (Settings → Permalinks → Save), or use the fallback form above

---

## Configuration & Hardening

### Authentication (Application Passwords)

- Each user can create an **Application Password** from  
  **Users → Profile → Application Passwords**
- The client authenticates with **Basic Auth**:  
  `Authorization: Basic base64(username:app_password)`

> On some servers, PHP does not receive the `Authorization` header.  
> Add this to your site's `.htaccess` (inside your site root):
>
> ```apache
> # Pass HTTP Authorization to PHP (required for Application Passwords)
> RewriteEngine On
> RewriteCond %{HTTP:Authorization} .
> RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
> ```

### MAMP Authentication Header Configuration

#### 1. Enable Apache Rewrite Module
Open MAMP's Apache configuration file:
- **Mac**: `/Applications/MAMP/conf/apache/httpd.conf`
- **Windows**: `C:\MAMP\conf\apache\httpd.conf`

Find and uncomment this line (remove the #):
```apache
LoadModule rewrite_module modules/mod_rewrite.so
```

#### 2. Configure Authorization Header Passing
Add this line to the same `httpd.conf` file (in the directory section or near the end):
```apache
SetEnvIf Authorization .+ HTTP_AUTHORIZATION=$0
```

#### 3. Restart MAMP
Completely restart MAMP for changes to take effect.

> **Note**: These changes are required because MAMP doesn't pass HTTP Authorization headers by default, which prevents WordPress Application Passwords from working with REST API authentication.

### Configuration (filters)

You can customize **maximum upload size** and the **allowed MIME types** using WordPress filters
(from your theme's `functions.php` or a small must-use plugin).

#### Max upload size

Default: **50 MB**. Return a value in **bytes**.

```php
// Example: 200 MB
add_filter('pfu_max_upload_bytes', function () {
    return 200 * 1024 * 1024;
});

// Example: 1 GB
add_filter('pfu_max_upload_bytes', fn () => 1024 * 1024 * 1024);
```

> Note: PHP/server limits must also allow the requested size:
> `upload_max_filesize`, `post_max_size`, and possibly proxy limits.

#### Allowed MIME types

Default allowlist:

* `application/zip`
* `image/jpeg`
* `image/png`
* `application/pdf`

Override completely:

```php
add_filter('pfu_allowed_mime_types', function ($mimes) {
    return [
        'application/zip',
        'application/pdf',
        'image/jpeg',
        'image/png',
        'text/plain',
    ];
});
```

Or extend the defaults:

```php
add_filter('pfu_allowed_mime_types', function ($mimes) {
    $mimes[] = 'text/plain';
    $mimes[] = 'video/mp4';
    return array_values(array_unique($mimes));
});
```

**API behavior on violations**

* Files exceeding the limit → **413 Payload Too Large**
* Unsupported MIME types → **415 Unsupported Media Type**
* Responses include a human-readable limit (e.g., `limitHuman: "50.00 MB"`)

---

## Endpoints

### 1) Ping (auth check)
- **GET** `/wp-json/fileuploader/v1/ping`  
  **or** `index.php?rest_route=/fileuploader/v1/ping`

**cURL**
```bash
# without auth (should return 401/403)
curl -s 'https://example.com/index.php?rest_route=/fileuploader/v1/ping'

# with Application Password
curl -s -u 'USERNAME:APP_PASSWORD' \
  'https://example.com/index.php?rest_route=/fileuploader/v1/ping'
```

### 2) Upload (single file)

* **POST** `/wp-json/fileuploader/v1/upload`  
  **or** `index.php?rest_route=/fileuploader/v1/upload`
* Multipart form field name: **`file`**

**cURL**

```bash
curl -v -u 'USERNAME:APP_PASSWORD' \
  -X POST \
  -F 'file=@/path/to/file.zip;type=application/zip' \
  'https://example.com/index.php?rest_route=/fileuploader/v1/upload'
```

**Response (201)**

```json
{
  "ok": true,
  "file": "file.zip",
  "path": "/var/www/.../wp-content/uploads/media/private-file-uploader/alice/file.zip",
  "url": "https://example.com/wp-content/uploads/media/private-file-uploader/alice/file.zip",
  "mime": "application/zip",
  "owner": "alice",
  "location": "media/private-file-uploader/alice"
}
```

### 3) List files

* **GET** `/wp-json/fileuploader/v1/files`
* Query parameters:
  - `page` (int, default: 1) - Page number
  - `per_page` (int, default: 1000, max: 1000) - Items per page
  - `order` (string, default: "desc") - Sort order: `asc` or `desc`

**cURL**

```bash
curl -u 'USERNAME:APP_PASSWORD' \
  'https://example.com/wp-json/fileuploader/v1/files?page=1&per_page=50&order=desc'
```

**Response (200)**

```json
{
  "ok": true,
  "items": [
    {
      "name": "document.pdf",
      "url": "https://example.com/wp-content/uploads/.../document.pdf",
      "size": 1048576,
      "mime": "application/pdf",
      "modified": 1704067200
    }
  ],
  "owner": "alice",
  "count": 1,
  "page": 1,
  "per_page": 50,
  "total": 1,
  "total_pages": 1,
  "order": "desc"
}
```

### 4) Delete file

* **DELETE** `/wp-json/fileuploader/v1/files/{filename}`

**cURL**

```bash
curl -u 'USERNAME:APP_PASSWORD' \
  -X DELETE \
  'https://example.com/wp-json/fileuploader/v1/files/document.pdf'
```

**Response (200)**

```json
{
  "ok": true,
  "deleted": "document.pdf",
  "owner": "alice"
}
```

### 5) File metadata (HEAD)

* **HEAD** `/wp-json/fileuploader/v1/files/{filename}`
* Returns metadata in headers without body content

**cURL**

```bash
curl -I -u 'USERNAME:APP_PASSWORD' \
  'https://example.com/wp-json/fileuploader/v1/files/document.pdf'
```

**Response Headers**

```
HTTP/1.1 200 OK
Content-Length: 0
Last-Modified: Mon, 01 Jan 2024 12:00:00 GMT
ETag: "abc123..."
X-PFU-Size: 1048576
X-PFU-Mime: application/pdf
X-PFU-Name: document.pdf
X-PFU-Owner: alice
```

---

## Admin Interface

The plugin provides a comprehensive admin interface accessible from **WP Admin → Private Uploader**:

### Overview Page
- Displays current upload policy (max size, allowed MIME types)
- Shows PHP server limits (upload_max_filesize, post_max_size, memory_limit)
- Warns if PHP limits are below plugin policy
- Quick access to Library and Settings

### Library Page
- Browse all uploaded files for the current user
- Visual previews for images, MIME type icons for other files
- File information: name, size, modification date, MIME type
- Delete files with confirmation

### Settings Page (Admins only)
- Configure maximum upload size
- Manage allowed MIME types
- Settings can be overridden via filters for advanced customization

### Safe Deactivate
- Choose what to do with user files before deactivation:
  - **Delete all files**: Removes all uploaded files permanently
  - **Keep files (block access)**: Keeps files and writes deny rules for Apache/IIS
- Provides configuration snippets for Apache, IIS, and Nginx

### User Deletion Options
When deleting a user, admins can choose:
- **Delete all files**: Remove the user's storage directory
- **Reassign to another user**: Move files to another user's directory
- **Keep files (manual blocking)**: Keep files on disk (manual server rules required)

---

## Storage layout

```
wp-content/uploads/
  media/private-file-uploader/
    <username>/
      index.html
      <uploaded files...>
```

* The directory is created on first upload
* `index.html` is added to discourage directory listing (if enabled server-side)

---

## Troubleshooting

* **404 on `/wp-json/...`**: Use fallback  
  `index.php?rest_route=/fileuploader/v1/...` or fix rewrite rules  
  (flush permalinks; ensure `.htaccess` is in site root and `mod_rewrite` enabled)

* **401 Unauthorized** with credentials:
  * Verify **Application Password** is correct and copied without spaces
  * Confirm the **Authorization** header reaches PHP (see `.htaccess` snippet)
  * Test core endpoint:
    ```bash
    curl -v -u 'USERNAME:APP_PASSWORD' \
      'https://example.com/index.php?rest_route=/wp/v2/users/me'
    ```
    If this fails, it's an **auth transport** issue (not the plugin)

* **"Missing parameter: file" (400)**:
  * Ensure you send **multipart/form-data** with field name **`file`** (`-F 'file=@...'`)
  * Do not set `Content-Type` manually; `curl -F` will do it

* **413 Payload Too Large**:
  * File exceeds the configured limit
  * Increase limit via Settings page or `pfu_max_upload_bytes` filter
  * Ensure PHP `upload_max_filesize` and `post_max_size` are also sufficient

* **415 Unsupported Media Type**:
  * File MIME type is not in the allowed list
  * Add MIME type via Settings page or `pfu_allowed_mime_types` filter

---

## Development

* Main file: `private-file-uploader.php`
* Core logic: `src/Plugin.php` (routes, upload logic, file operations)
* Admin interface: `src/Admin.php` (admin pages, settings, user management)
* No database schema changes; the plugin uses WP upload APIs (`wp_handle_sideload`) and per-user directories

Run a quick local ping:

```bash
curl -s 'http://localhost/wp/index.php?rest_route=/fileuploader/v1/ping'
```

---

## Security Features

- **Per-user isolation**: Each user has a separate directory
- **Path traversal protection**: Strict filename validation and realpath checks
- **Symlink prevention**: Rejects symbolic links
- **MIME type validation**: Content-based detection (finfo) with fallback
- **Size limits**: Configurable maximum upload size
- **Authentication required**: All endpoints require valid Application Passwords
- **Directory listing protection**: index.html files in upload directories

---

## License

MIT – See [LICENSE](./LICENSE).