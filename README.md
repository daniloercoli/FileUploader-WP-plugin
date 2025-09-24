# Private File Uploader (WordPress Plugin)

Custom REST endpoints to accept file uploads into **per-user directories**.  
Designed to pair with the **Private File Uploader** mobile app (React Native).  
Authentication uses **WordPress Application Passwords** over HTTPS.

> **Note:** This repository contains the **server component**.  
> The React Native client integrates with these endpoints.

---

## What it does

- Exposes REST endpoints under:  
  `GET  /wp-json/fileuploader/v1/ping`  
  `POST /wp-json/fileuploader/v1/upload` (multipart `file` field)
- Stores uploaded files under:  
  `wp-content/uploads/media/private-file-uploader/<username>/...`
- Scopes the upload directory **per-user** (prevents mixing user files).
- Leaves an `index.html` in each folder to discourage directory listing.

---

## Requirements

- WordPress **5.6+** (Application Passwords introduced in core)
- PHP **8.0+** (tested with 8.1/8.2/8.3)
- HTTPS strongly recommended in production

---

## Installation

1. Copy this plugin folder into:  
   `wp-content/plugins/wp-private-file-uploader/`
2. In WP Admin → **Plugins**, activate **Private File Uploader**.
3. Ensure the REST API is reachable:
   - Rewrite form (pretty): `https://example.com/wp-json/`  
   - Fallback form: `https://example.com/index.php?rest_route=/`
4. (Optional) If `/wp-json` returns 404 on local Apache, flush permalinks  
   (Settings → Permalinks → Save), or use the fallback form above.

---

## Authentication (Application Passwords)

- Each user can create an **Application Password** from  
  **Users → Profile → Application Passwords**.
- The client authenticates with **Basic Auth**:  
  `Authorization: Basic base64(username:app_password)`

> On some servers, PHP does not receive the `Authorization` header.  
> Add this to your site’s `.htaccess` (inside your site root):
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
````

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

---

## Storage layout

```
wp-content/uploads/
  media/private-file-uploader/
    <username>/
      index.html
      <uploaded files...>
```

* The directory is created on first upload.
* `index.html` is added to discourage directory listing (if enabled server-side).

---

## Configuration & Hardening (next iterations)

* Allowlist MIME types and maximum upload size (plugin options).
* Optional HTTPS-only enforcement for REST requests.
* Additional endpoints:

  * `GET /files` (list files for the authenticated user)
  * `DELETE /files/{filename}` (safe deletion with traversal protection)

---

## Troubleshooting

* **404 on `/wp-json/...`**: Use fallback
  `index.php?rest_route=/fileuploader/v1/...` or fix rewrite rules
  (flush permalinks; ensure `.htaccess` is in site root and `mod_rewrite` enabled).
* **401 Unauthorized** with credentials:

  * Verify **Application Password** is correct and copied without spaces.
  * Confirm the **Authorization** header reaches PHP (see `.htaccess` snippet).
  * Test core endpoint:

    ```bash
    curl -v -u 'USERNAME:APP_PASSWORD' \
      'https://example.com/index.php?rest_route=/wp/v2/users/me'
    ```

    If this fails, it’s an **auth transport** issue (not the plugin).
* **“Missing parameter: file” (400)**:

  * Ensure you send **multipart/form-data** with field name **`file`** (`-F 'file=@...'`).
  * Do not set `Content-Type` manually; `curl -F` will do it.

---

## Development

* Main file: `private-file-uploader.php`
* Core code: `src/Plugin.php` (routes, upload logic)
* No DB schema changes; the plugin uses WP upload APIs (`wp_handle_sideload`) and a per-user directory.

Run a quick local ping:

```bash
curl -s 'http://localhost/wp/index.php?rest_route=/fileuploader/v1/ping'
```

---

## License

MIT — See [LICENSE](./LICENSE).

```