=== REST & Login Shield ===
Contributors: weblixpl
Tags: security, brute force, rest api, login, hardening
Requires at least: 5.8
Tested up to: 6.5
Requires PHP: 7.4
Stable tag: 1.2.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Minimal WordPress security hardening: blocks REST API user enumeration, hides server metadata, and protects wp-login.php against brute force attacks.

== Description ==

REST & Login Shield is a small, zero-configuration security plugin that closes the most common information-leak and brute-force attack vectors on WordPress sites.

**What it does:**

* **Blocks REST API user enumeration** — returns 404 on `/wp-json/wp/v2/users/` for unauthenticated requests so attackers cannot harvest your usernames.
* **Hides server metadata** — strips `description`, `gmt_offset`, `timezone_string` from `/wp-json/` to reduce fingerprinting.
* **Blocks author URL enumeration** — redirects `?author=N` requests and `/author/USERNAME/` archive pages to the home page with a 301, and masks usernames in RSS feeds (`<dc:creator>`).
* **Brute force lockout** — after too many failed login attempts from one IP, blocks that IP for a configurable period. IP whitelist with CIDR support is included.

**No bloat:** four protections, one settings page, no third-party calls, no telemetry. Works alongside Wordfence, iThemes Security, and similar plugins without conflicts.

**Languages:** English, Polish, Danish, German, Czech, Slovak, French.

**Automatic updates** from GitHub releases are enabled out of the box — you do not need the WordPress.org plugin directory to receive updates.

== Installation ==

1. Download the latest release ZIP from [GitHub Releases](https://github.com/weblixpl/rest-login-shield/releases).
2. In WordPress admin, go to **Plugins → Add New → Upload Plugin**, choose the ZIP, and activate.
3. Configure under **Settings → REST & Login Shield**.

For bulk deployment across many sites, the plugin can be installed through WP Toolkit (cPanel/Plesk) or any multisite management tool (MainWP, ManageWP).

== Frequently Asked Questions ==

= Will this break the REST API? =

No. Only the `/wp/v2/users` endpoint is hidden, and only for unauthenticated requests. All other endpoints continue to work normally. Logged-in users (including your application) still have full access.

= Can I accidentally lock myself out? =

Add your IP to the **IP whitelist** in Settings → REST & Login Shield before you start testing. The whitelist supports single IPs and CIDR ranges. A successful login also clears the counter for your IP.

= Does this work behind Cloudflare / a proxy? =

Yes. The plugin reads the client IP from `CF-Connecting-IP`, `X-Real-IP`, or `X-Forwarded-For` headers in that order, falling back to `REMOTE_ADDR`.

= How do I roll out updates? =

Push a new tag or GitHub release to `weblixpl/rest-login-shield`. Within 12 hours, every site where the plugin is installed will show an update notification in the WordPress admin, exactly like a plugin from the official repository.

== Changelog ==

= 1.2.1 =
* **Update channel moved off the GitHub API** — auto-update now reads a static `metadata.json` from GitHub Pages instead of calling `api.github.com`. The previous channel hit GitHub's 60-requests-per-hour-per-IP unauthenticated rate limit on shared hosting and triggered abuse detection when many client sites checked the same repository in the same window, leaving sites stuck on old versions with a "Could not determine if updates are available" error. The new channel is served from a static CDN with no rate limit, no token required, and no per-site configuration.
* No behavior changes, no settings changes. After upgrading once, every future release will be picked up automatically.

= 1.2.0 =
* **Security fix**: author enumeration protection was incomplete. With the toggle enabled, `?author=N` was still being redirected by WordPress core's canonical redirect to `/author/USERNAME/` before the plugin could intercept, leaking the user login. The handler now runs at priority 1 on `template_redirect` and additionally hooks `redirect_canonical` to override core's behavior.
* **Author archives blocked**: `/author/USERNAME/` pages now return a 301 to the home page when the author enumeration toggle is enabled. Previously these pages returned 200 and confirmed the existence of a username.
* **RSS feed leak fixed**: `<dc:creator>` in RSS feeds now shows the site name instead of the user login. Previously the feed exposed the WordPress login of every post author to anonymous visitors.
* Upgrade is strongly recommended for any site visible on the public internet — the three vectors above were actively used to harvest usernames before brute-force attempts.

= 1.1.0 =
* New protection: **Disable comments** — optional toggle that completely removes the comment system sitewide. Blocks new submissions via forms, REST API (`/wp-json/wp/v2/comments`), and XML-RPC (`wp.newComment`, pingbacks). Hides the comment UI in the admin and on the frontend, disables pingbacks/trackbacks, and removes comment-related dashboard widgets. Existing comments are preserved (not deleted). Default: off.
* Translations for the new UI in all six supported languages.

= 1.0.1 =
* **Security fix**: `get_client_ip()` no longer trusts `CF-Connecting-IP`, `X-Real-IP`, or `X-Forwarded-For` headers by default. On a directly-exposed site these headers could be spoofed to bypass brute force lockout. A new **Trusted proxy** setting lets admins opt in (None / Cloudflare / X-Real-IP / X-Forwarded-For). Default is **None** — safe for sites not behind a proxy. Upgrade is strongly recommended.
* Added translations for the new setting in all six supported languages.

= 1.0.0 =
* Initial release.
* REST API user enumeration blocking.
* REST API metadata stripping.
* Author enumeration blocking.
* Brute force protection with IP whitelist (single IPs and CIDR).
* Settings page with blocked IPs table and recent attempt log.
* Translations: English, Polish, Danish, German, Czech, Slovak, French.
* Automatic updates from GitHub releases.
