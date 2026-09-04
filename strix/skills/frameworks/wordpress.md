---
name: wordpress
description: Security testing playbook for WordPress plugins covering AJAX/REST entry points, $wpdb injection, nonce/capability guard verification, and CVE-quality reporting
---

# WordPress (Plugins)

Vulnerability hunting in WordPress **plugins** (and themes, which share the
same hook/capability/escaping model). WordPress's own security model —
nonces, capability checks, `$wpdb->prepare`, the `esc_*`/`sanitize_*` escaping
APIs, the `wp_ajax_*` / `wp_ajax_nopriv_*` hook split — is not something
generic PHP static analysis understands. A generic `p/php` semgrep pass or a
plain "grep for `$_GET`" sweep either misses these bugs entirely or drowns
them in noise, because the vulnerable pattern is not "unsafe PHP," it's
"safe-looking PHP missing the one WordPress-specific guard it needed." That
gap is where the real, CVE-worthy plugin bugs live — this skill is the
methodology for finding them with the discipline to report only what is
actually real.

**Scope.** WordPress **core** is out of scope for this skill: it has its own
dedicated security team, a mature bug-bounty program, and a far smaller,
far more hardened attack surface than the plugin ecosystem — don't spend
budget hunting there. The overwhelming majority of WordPress CVEs are in
plugins and themes, and that is where this methodology is aimed.

## Attack Surface

WordPress exposes untrusted input to plugin code through a fixed set of
seams. Every plugin has some subset of these; enumerate all of them before
picking a target to trace.

- **AJAX handlers** — `add_action('wp_ajax_{action}', ...)` (logged-in) and
  `add_action('wp_ajax_nopriv_{action}', ...)` (**unauthenticated** —
  reachable by anyone who can hit `/wp-admin/admin-ajax.php`).
- **REST API routes** — `register_rest_route($namespace, $route, [...])`,
  gated (or not) by `permission_callback`.
- **Shortcodes** — `add_shortcode($tag, $callback)`; the callback receives
  `$atts` from wherever the shortcode is placed, which is attacker-controlled
  on any site where lower-privileged users, comments, or forums can embed
  shortcodes.
- **`admin-post.php` handlers** — `add_action('admin_post_{action}', ...)`
  (logged-in) and `add_action('admin_post_nopriv_{action}', ...)`
  (unauthenticated), the non-AJAX sibling of the same pattern.
- **Widgets** — `WP_Widget::update()` receives raw `$new_instance` from
  `$_POST` when an admin saves widget settings; `WP_Widget::widget()` renders
  it front-end.
- **Meta boxes / `save_post`** — custom fields saved via the `save_post`
  hook, reading `$_POST` directly; needs its own nonce
  (`wp_nonce_field`/`wp_verify_nonce`) and `current_user_can('edit_post',
  $post_id)` — the generic "can edit *some* post" capability is not the same
  check.
- **Settings API** — `register_setting($group, $name, $args)`; the
  `sanitize_callback` argument is often missing or too weak, which is a
  direct path to stored XSS on the options/settings page.
- **`wp_cron`** — scheduled callbacks are not directly attacker-reachable in
  most cases, but check whether the action name is also triggerable via
  `admin-ajax.php` or an unauthenticated `wp-cron.php` hit with
  attacker-influenced stored data.
- **Raw superglobals** — `$_GET`, `$_POST`, `$_COOKIE`, `$_SERVER`
  (`HTTP_X_FORWARDED_FOR`, `HTTP_REFERER`, `REQUEST_URI` are frequently
  trusted without justification), and especially `$_REQUEST` (silently
  merges GET+POST+COOKIE — a plugin author reaching for `$_REQUEST` out of
  laziness is a signal worth following). Note WordPress adds slashes to
  every superglabal (`wp_magic_quotes()`); a plugin should call
  `wp_unslash()` before using the value — a custom sanitizer written against
  the slashed form is its own subtle bug class.

## Entry Points — Enumerate Every One, Not Just the Loudest

**This is `source_aware_discovery.md`'s instance discipline applied to
WordPress hooks: a plugin with six registered AJAX actions is six
candidates, not one "the AJAX handler is unsafe" note.** Each hook
registration is its own entry point with its own reachability and its own
guards — enumerate them all before tracing any single one:

```bash
# Every AJAX action — split priv/nopriv, they have different reachability
rg -n "add_action\s*\(\s*['\"]wp_ajax_nopriv_" --type php   # unauthenticated
rg -n "add_action\s*\(\s*['\"]wp_ajax_"          --type php   # logged-in (all roles unless gated)

# Every REST route — read permission_callback inline, don't assume
rg -n "register_rest_route\s*\(" --type php -A8

# Every admin-post handler
rg -n "add_action\s*\(\s*['\"]admin_post_" --type php

# Shortcodes, widgets, settings sanitizers
rg -n "add_shortcode\s*\(" --type php
rg -n "class\s+\w+\s+extends\s+WP_Widget" --type php
rg -n "register_setting\s*\(" --type php -A3
```

Fold these hits into the shared `/workspace/.source-aware/entry_points.md`
map (see `custom/source_aware_sast.md`'s Entry-Point Map step) rather than
keeping them in a separate note — that's the one file every later agent
reads instead of re-deriving this list.

For a `wp_ajax_nopriv_{action}` and `wp_ajax_{action}` pair registered to the
**same callback**, treat it as a strong signal the author intended
unauthenticated reach — the only thing that can still make it safe is an
in-function guard, never the hook name itself. When they point at
**different** callbacks, check the nopriv one first: it is almost always the
smaller, less-reviewed code path.

## Dangerous Sinks by Vulnerability Class

Trace every entry point above forward to whichever of these it reaches. Each
pattern below is a *candidate*, not a finding — see "The Real Control"
before you report anything.

**SQL injection — the #1 WordPress plugin CVE class.**
```php
// Vulnerable: interpolated value
$wpdb->get_results("SELECT * FROM {$wpdb->prefix}items WHERE id = $id");
$wpdb->query("...ORDER BY " . $_GET['sorting'] . " " . $_GET['order']);

// Safe: value placeholder
$wpdb->get_results($wpdb->prepare(
    "SELECT * FROM {$wpdb->prefix}items WHERE id = %d", $id
));
```
Flag every `$wpdb->query` / `get_results` / `get_var` / `get_row` / `get_col`
call and check whether the SQL string contains a variable **outside** a
`$wpdb->prepare()` call. **The identifier trap** (this is the exact shape of
CVE-2024-1071-class bugs — an `orderby`/`sorting`/`dbid`-style parameter used
as a column name or sort direction): `$wpdb->prepare("... ORDER BY %s", $col)`
still doesn't make `$col` safe as a *column name* — `%s` quotes it as a
string literal, which usually just breaks the query rather than validating
it as an identifier. `prepare()` placeholders only cover **values**, never
table/column names or `ORDER BY`/`ASC`/`DESC` direction keywords. The only
correct fix for an identifier is an allowlist (a `switch`/`in_array` against
a fixed set of known-safe column names), never a placeholder. A plugin that
passes a request parameter straight into `ORDER BY` — prepared or not — is
the pattern to look for first.

**Cross-site scripting.**
```php
// Vulnerable
echo $_GET['name'];
echo "<div class='" . $_POST['class'] . "'>";

// Safe, context-matched
echo esc_html( $_GET['name'] );
echo "<div class='" . esc_attr( $_POST['class'] ) . "'>";
```
`esc_html()` / `esc_attr()` / `esc_url()` / `esc_js()` / `wp_kses()` /
`wp_kses_post()` are context-specific — an escaping call being *present* is
not the same as it being the *right* one for where the value lands (an
`esc_html()`'d value dropped into an `href=` attribute is still
attribute-breakable; `esc_url()` is what belongs there). Read the exact sink
context, not just whether an `esc_*`/`sanitize_*` name appears nearby.

**CSRF (missing/weak nonce).**
```php
// Vulnerable: no nonce check before a state change
function my_plugin_delete_item() {
    wpdb->query( "DELETE FROM ... WHERE id = " . $_POST['id'] );
}

// Safe
function my_plugin_delete_item() {
    check_ajax_referer( 'my_plugin_delete', 'nonce' ); // dies on failure
    ...
}
```
`wp_ajax_*` (vs. `wp_ajax_nopriv_*`) only means "requires a session" — it
implies **nothing** about CSRF. A logged-in victim's browser can still be
made to fire the request. Every state-changing AJAX/admin-post handler needs
`wp_verify_nonce()` / `check_admin_referer()` / `check_ajax_referer()`.

**Broken access control / privilege escalation.**
```php
// Vulnerable: checks nothing about role
if ( is_user_logged_in() ) { update_option( 'my_plugin_license_key', $_POST['key'] ); }

// Vulnerable: capability every subscriber already has
if ( current_user_can( 'read' ) ) { ... }

// Safe
if ( current_user_can( 'manage_options' ) ) { ... }
```
`current_user_can($cap)` is only as strong as `$cap`. `is_user_logged_in()`
checks nothing about role. A missing capability check on a `wp_ajax_nopriv_*`
action that performs an admin-level operation (option changes, user role
changes, data export) is the single most common WordPress plugin privilege
escalation pattern.

**File handling — path traversal, arbitrary read/write/delete, upload RCE.**
```php
// Vulnerable
unlink( WP_CONTENT_DIR . '/uploads/' . $_GET['file'] );
include $_GET['template'] . '.php';

// Upload RCE: extension check missing or bypassable
move_uploaded_file( $_FILES['file']['tmp_name'], $upload_dir . $_FILES['file']['name'] );
```
Any `unlink` / `file_get_contents` / `fopen` / `copy` / `move_uploaded_file`
/ `WP_Filesystem` call taking a user-influenced filename or path is a path
traversal candidate; combined with `.php`/`.phtml`/double-extension upload
acceptance (a missing or bypassable check against `wp_check_filetype()`, or
a widened `upload_mimes` filter), it's remote code execution.

**PHP object injection.**
```php
$data = unserialize( $_COOKIE['plugin_data'] ); // vulnerable
```
Requires a usable gadget chain (a class with an exploitable `__wakeup`,
`__destruct`, or similar magic method reachable from an active plugin or
WordPress core itself) to actually be exploitable — say explicitly whether
you found a real gadget or are flagging the sink alone as an
`open_proof_gap`. Don't overclaim severity without one.

**SSRF.**
```php
// Vulnerable: no destination restriction
$response = wp_remote_get( $_POST['feed_url'] );

// wp_safe_remote_get() already blocks loopback/private ranges by default
```
`wp_remote_get()`/`wp_remote_post()` (or raw `curl`) taking a user-supplied
URL is the pattern; `wp_safe_remote_get()`/`wp_safe_remote_post()` already
reject internal/loopback destinations unless the `reject_unsafe_urls` filter
has been disabled — check for that filter before ruling a `wp_safe_remote_*`
call safe.

**LFI/RFI.**
```php
include $_GET['tpl'] . '.php'; // template-picker feature, classic pattern
```
`include`/`require`/`include_once`/`require_once` with any part of the path
built from request data — commonly hiding inside an email-template or
page-template "chooser" feature.

## The Real Control — Verify the Guard, Don't Assume It

This is `counterevidence.md`'s discipline applied to the WordPress-specific
guards above. Each of these *looks* like it settles the question; none of
them do on their own.

- **`$wpdb->prepare()` present ≠ safe.** Check the placeholder *count and
  type* matches the interpolated values, and specifically that no
  placeholder is standing in for a table/column name or sort direction
  (the identifier trap above). `ruled_out` requires you to have read the
  literal SQL string produced and confirmed every attacker-reachable
  variable lands in a value placeholder, not the query skeleton.
- **A capability check exists ≠ the right capability.** Read the actual
  string passed to `current_user_can()`. `read`, `exist`, and
  `upload_files` are held by nearly every registered user; only
  `manage_options`, `edit_others_posts`, `delete_users`, etc. actually gate
  privileged operations. State which capability was checked and why it does
  or doesn't match the operation's real privilege level.
- **A nonce check exists ≠ it covers this action.** `wp_verify_nonce($token,
  $action)` / `check_ajax_referer($action)` bind to a specific `$action`
  string. A nonce created for `'my_plugin_view'` and checked against that
  same string on a `'my_plugin_delete'` handler (or a shared/generic nonce
  reused across every action in the plugin) is not a control on the delete
  path — a mismatched or overly-generic action string is a broken guard,
  not a working one.
- **`check_ajax_referer()`/`check_admin_referer()` called with `$die = false`
  ≠ it stops execution.** Both default to killing the request on failure,
  but a plugin can pass `false` for the second/third argument to get a
  boolean back instead — if the return value is never checked afterward,
  the "check" runs and does nothing. Read what happens to the return value.
- **The nonce/capability guard runs on the `wp_ajax_*` handler ≠ it runs on
  the `wp_ajax_nopriv_*` sibling.** These are separate function
  registrations (even when they point at the same callback, confirm you're
  reading the actual reachable code path for *both* hook names, not
  assuming symmetry).
- **`sanitize_text_field()` / `absint()` present ≠ safe for every sink.**
  `sanitize_text_field()` strips tags and extra whitespace — it is not a SQL
  escaper and does nothing to stop a `$wpdb->query()` concatenation.
  `absint()` genuinely does neutralize a numeric-context SQLi (it forces an
  integer), but check that the sink actually is a bare `$wpdb->query()`
  wanting an int and not, say, a filename or shell argument where a
  different rule applies. Match the sanitizer to the specific sink, per
  `counterevidence.md`'s "generic trust in a library" rule.

Confirmed / ruled_out / open_proof_gap apply exactly as in
`counterevidence.md`: a present-and-correctly-matched guard on the
attacker-reachable path is `ruled_out` (name the guard, the action string or
capability, and confirm it runs before the sink); a missing, mismatched, or
fail-open guard is a live candidate; "I couldn't tell if this route is
exposed" or "the nonce looked present" without reading the matched action
string is `open_proof_gap`, never `ruled_out`.

## 0-Day Hunting — Target Triage and Exhaustive Coverage

Everything above assumes a plugin already worth analyzing. The harder,
higher-value case is finding brand-new, undisclosed vulnerabilities in
freshly-published or under-scrutinized plugins with no known CVE to anchor
the search — CVE-worthy discovery, not just confirming an already-reported
bug. Two things change here: which plugin is worth the budget, and how
exhaustively you must cover the one you pick.

### High-Yield Target Signals

When you can choose which plugin to deep-dive, triage on the combination of
**attack surface** (is there anything worth attacking) and **low-maturity
signals** (is it likely to have been done carelessly). Either alone is a
weak signal — a plugin with real attack surface but no maturity red flags is
probably fine; a trivial plugin with sloppy code has nothing worth reaching.
Prioritize where both are present.

**Attack surface present:**
- Registered `wp_ajax_nopriv_*` actions
- `register_rest_route()` calls, especially with `permission_callback`
  missing or `__return_true`
- `$wpdb` usage, file operations, `unserialize()` calls, forms

**Low-maturity ("bug likelihood") signals:**
- Raw `$_REQUEST`/`$_GET`/`$_POST` used directly at a sink with no
  intermediate sanitizer call visible
- `$wpdb` calls built with visible string concatenation instead of
  `$wpdb->prepare()`
- An AJAX/admin-post handler with no `wp_verify_nonce`/`check_ajax_referer`/
  `check_admin_referer` call anywhere in its body
- No `current_user_can()` call at all in a handler that clearly performs a
  privileged operation
- Old/deprecated patterns: `mysql_*` calls, `extract($_POST)`, bare
  `eval()`, direct `$GLOBALS` manipulation — outdated-code smells even when
  not themselves the sink
- A `readme.txt` with very few "Tested up to" bumps (infrequent
  maintenance), or a recent first release with more than trivial
  functionality (rushed initial development)
- A low active-install count combined with real functionality — less
  scrutiny and fewer prior bug reports, not a "hello world" plugin

A plugin exposing `wp_ajax_nopriv_export_data` (attack surface) where that
same read shows `$_REQUEST['id']` concatenated straight into a
`$wpdb->query()` (maturity signal) earns deep-trace budget before a plugin
with the same action but a clean `$wpdb->prepare()` call.

### Exhaustive Coverage — the False-Negative Guard

Once you commit to a plugin, there is no known CVE to anchor on — the
undisclosed bug could be in any entry point that accepts input, so partial
coverage is not an option. This inverts the usual "chase the loudest
candidate first" instinct: enumerate **every** source before deep-tracing
any single one, or the actual bug is exactly the kind of thing a partial
sweep walks past in favor of the first plausible-looking hit.

- Enumerate every `wp_ajax_nopriv_*` and `wp_ajax_*` action, every
  `register_rest_route()` call (read every `permission_callback`, not just
  the first few routes), every shortcode, admin-post handler, widget
  `update()` method, and settings sanitizer — per "Entry Points" above, in
  full, not a sample.
- Trace each to every sink it reaches — a handler often has more than one
  attacker-controlled parameter feeding different sinks; do not stop at the
  first one you confirm safe.
- `record_coverage` every surface swept, including the ones that came back
  `no_issue_found`/`ruled_out` — per `counterevidence.md`, this is what
  distinguishes "checked and clean" from "never looked," which matters when
  you are effectively claiming the rest of the plugin has nothing else worth
  reporting.
- Exhaustive breadth across every entry point is worth more here than one
  deep, narrow trace while several other entry points sit unexamined.

### FP Discipline Is Absolute for a 0-Day Claim

A submitted 0-day that turns out to be a false positive — the `$wpdb` call
was actually prepared, the handler had a guard you missed reading, the
capability check was correct — burns researcher reputation permanently, in
a way an internal engagement report's occasional miss does not. There are
no exceptions here: every 0-day claim needs the complete verified chain from
"The Real Control" above — a named, checked status for every relevant guard,
a concrete reachable path, and, wherever a live instance exists, a working
exploit, not a plausible-looking static read. When that bar isn't cleared,
the correct outcome is `open_proof_gap` or a `confidence: low` static-only
report with the exact gap named — never a claim rounded up to look more
finished than the evidence supports.

## Testing Methodology

1. **Detect the target is a WordPress plugin/theme.** A `Plugin Name:` (or
   `Theme Name:`) header comment block in the main PHP file, a `readme.txt`
   with WordPress-style headers (`Stable tag:`, `Requires at least:`,
   `Tested up to:`), a `wp-content/plugins/<slug>/` (or `wp-content/themes/`)
   path, or heavy `add_action`/`add_filter`/`$wpdb`/`register_activation_hook`
   usage. Record the declared version (`Version:` header / readme `Stable
   tag:`) up front — you need it for reporting. When choosing among several
   candidate plugins rather than analyzing an already-assigned one, apply
   "High-Yield Target Signals" above before committing budget to a deep dive.
2. **Enumerate every entry point** with the sweeps under "Entry Points"
   above. Do not stop at the first `wp_ajax_nopriv_*` you find — list all of
   them.
3. **Run `semgrep --config p/php`** (and `--config auto`) as a light triage
   layer only — it catches generic PHP mistakes (raw `eval`, obvious
   concatenated queries) but has no concept of nonces, capabilities, or the
   WordPress escaping API, so it will both miss most of what matters here
   and flag things that turn out to be `ruled_out`. Treat its output as a
   places-to-look list, never as a verdict. (No WordPress-specific semgrep
   ruleset is wired into the sandbox yet — this methodology's source-to-sink
   tracing is the primary tool, per `source_aware_sast.md`'s own
   anti-patterns: "do not treat scanner output as final truth.")
4. **Map each entry point to its sink(s)** by reading the handler function
   and everything it calls, per "Dangerous Sinks" above. Keep the wrapper
   (the hook registration) and the concrete sink both visible in your
   notes — the wrapper proves reachability, the sink is where the bug is.
5. **Verify every guard on the path** per "The Real Control" before treating
   anything as confirmed.
6. **Build a concrete exploitability trace**: entry point (HTTP-reachable
   action/route) → every intermediate call → the sink, stating who can
   reach it (unauthenticated / any logged-in role / a specific capability)
   and under what preconditions. This is the same evidence bar as
   `dependency_cve_scanning.md`'s source-to-sink trace requirement, applied
   to first-party plugin code instead of a dependency.
7. **Validate dynamically wherever there is a live instance** in scope
   (a WordPress install with the plugin active). Static tracing alone,
   without a runtime target, is still reportable per
   `counterevidence.md`'s "Reporting an Unconfirmed Candidate" — at
   `confidence: medium` or `low`, with the missing runtime proof named
   explicitly. The sandbox has no PHP runtime or WordPress install, so a
   pure source-only engagement is expected to fall into this category;
   don't inflate confidence to compensate.

## Validation

- **Unauthenticated AJAX PoC:** a bare `curl` to
  `/wp-admin/admin-ajax.php` with `action={the wp_ajax_nopriv_ action}` and
  the minimal parameters to reach the sink, sent with no cookies —
  demonstrates the "unauthenticated" claim directly.
- **REST PoC:** a request to the route with no `Authorization`/cookie
  header when `permission_callback` is `__return_true` or absent.
- **Nonce-bypass demonstration:** show the same request fails without a
  nonce (or with a nonce for the wrong action) and succeeds with a
  validly-scoped one — or, for a missing-nonce finding, show the
  state-changing effect happens with no nonce parameter sent at all.
- **SQLi:** a boolean/time-based oracle through the confirmed parameter
  (`sqlmap --level` tuned to the specific parameter you traced, or a manual
  `' AND SLEEP(5)-- -`-style payload) — don't run a blind full `sqlmap -u`
  sweep over the whole site; you already know the vulnerable parameter from
  the trace.
- **Privilege escalation:** side-by-side requests as an unauthenticated /
  low-privilege / intended-privilege principal, showing the low-privilege
  request achieves the high-privilege effect.

## Ruled-Out Patterns (Do Not Report These)

- `$wpdb->prepare()` used with the interpolated value in a `%d`/`%s`/`%f`
  value placeholder, and the placeholder is genuinely a value, not an
  identifier.
- `current_user_can()` checked with a capability that actually matches the
  operation's privilege level, on the exact function that performs the
  state change (not a sibling display-only function).
- `check_ajax_referer($action)` / `wp_verify_nonce($token, $action)` with an
  action string that matches the nonce actually created for this specific
  operation, whose return value is checked (or defaults to dying) before
  the sink runs.
- Output passed through the escaping function matched to its actual sink
  context (`esc_url()` in an `href`, `esc_attr()` in an attribute,
  `esc_html()` in element content, `wp_kses_post()` where limited HTML is
  intentionally allowed).
- `wp_safe_remote_get()`/`wp_safe_remote_post()` with the default
  `reject_unsafe_urls` behavior intact.

## Impact

- SQL injection via `$wpdb`: full database read/write, often including the
  `wp_users` table (password hashes, can be paired with a weak-hash crack
  or session-token theft for account takeover).
- Unauthenticated privilege escalation: attacker-created administrator
  account, or an existing low-privilege account (self-registration, a
  standard "subscriber" role) escalating to admin.
- Upload-handler RCE: full server compromise via a webshell.
- Stored XSS in an admin-facing settings/list page: session/cookie theft
  from any administrator who views it — often a path to full site takeover
  even when the injection point itself is "just" a subscriber-level form.

## Reporting for CVE Credibility and Responsible Disclosure

WordPress plugin CVEs are judged on exactly the kind of noise this skill
exists to prevent — file each finding with:

- **Affected plugin and version(s).** The plugin's name/slug plus the
  `Version:`/`Stable tag:` you recorded during detection, as an upper bound
  ("confirmed in X.Y.Z; check the plugin's changelog for whether a later
  release already fixed it before assuming it's still open"). Never claim a
  version range you haven't checked.
- **Vulnerability class (`CWE`).** Set the specific `CWE-NNN` for the sink
  family (e.g. CWE-89 for the `$wpdb` SQLi pattern, CWE-862 for a missing
  `current_user_can()` check, CWE-352 for a missing nonce) — a CNA intake
  form asks for this explicitly; do not leave it for the reader to infer.
- **Exact vulnerable code** — repository-relative `file:line` for every hop
  in the trace (entry point, every intermediate call, the sink), using
  `code_locations` the same way `source_aware_discovery.md` asks for
  labeled entrypoint/root-control/sink locations elsewhere.
- **The full source-to-sink trace**, stated the way
  `dependency_cve_scanning.md` writes its reasoning: `entry point ->
  intermediate call -> sink`, naming exactly who can reach it and what (if
  anything) gates it.
- **A concrete, working PoC request** (the literal unauthenticated HTTP
  request that triggers it, not a description of one) — from the Validation
  section above.
- **WordPress-context impact**: which role tier is required to trigger it
  (unauthenticated / any authenticated role / a specific capability),
  whether multisite changes the blast radius, and what the practical
  consequence is (data exposure, account takeover, RCE).
- **A suggested fix.** Name the concrete change (e.g. "wrap the interpolated
  value in `$wpdb->prepare()` with a `%d` placeholder", "add
  `current_user_can('manage_options')` before the option write", "add
  `check_ajax_referer('plugin_action')` at the top of the handler") in
  `remediation_steps` — this is prose guidance for the plugin author, not a
  patch Strix applies; there is no working tree of someone else's plugin to
  submit a PR against here, so `fix_before`/`fix_after`/`apply_patch` don't
  apply the way they do on a white-box scan of the user's own repository.
- **Routing:** this is 0-day discovery in the plugin's own first-party code,
  not a known, already-published CVE in a dependency manifest — file it
  with `create_vulnerability_report`, never `create_dependency_report`
  (that tool is exclusively for already-published advisories found via
  lockfile/manifest scanning, per `dependency_cve_scanning.md`).
- Apply `counterevidence.md`'s full pre-report pass (argue the other side,
  record what you checked, set `confidence` honestly, state
  `severity_change_conditions`) before filing — a submitted-then-disputed
  WordPress CVE costs real reputation, and static-only findings without a
  live target should be `confidence: medium`/`low` with the gap named, not
  inflated to look more finished than the evidence supports.

### Responsible Disclosure

Finding and verifying the bug is this skill's job; **actually disclosing
it is a human decision and a human action, not something the agent
performs.** Strix has no tool for emailing a maintainer, filing with a CNA
(Patchstack, Wordfence, or WPScan all run WordPress-specific CVE-assignment
programs that accept researcher submissions), or posting to a public
tracker — and even if `agent_browser`/`web_search` could technically reach
one of those forms, do not use them to submit anything. Publishing or
notifying without the operator's decision is exactly the "no public PoC
before a patch" norm this section exists to protect.

The report you hand back should be **submission-ready** for the operator to
carry forward through the normal responsible-disclosure sequence: notify
the plugin maintainer (or the CNA directly) first, coordinate a fix and an
embargo before any public detail or PoC goes out, and let the CNA or
maintainer credit and assign the CVE once a patched version ships. State
this norm explicitly in your final message to the operator alongside the
report — a verified bug with no disclosure plan is not yet a responsibly
handled one.

## Tooling

No PHP runtime, WordPress install, or WordPress-specific static analyzer is
installed in the sandbox — `semgrep` and `ast-grep` parse PHP structurally
without needing one, so static analysis works, but nothing here can execute
the plugin's code locally. Treat this methodology's manual source-to-sink
tracing as primary, exactly as `source_aware_sast.md`'s anti-patterns
require, with these as triage layers:

- **`ripgrep`** — the highest-signal tool for this skill: every pattern
  under "Entry Points" and "Dangerous Sinks" above is a literal WordPress
  API function name, so a targeted `rg -n` sweep is precise, not a fuzzy
  pattern match. Prefer it over a full SAST pass for a quick first look.
- **`semgrep --config p/php`** (and `--config auto`) — generic PHP triage
  only; catches obvious `eval`/concatenation mistakes, has no WordPress
  vocabulary. A dedicated WordPress ruleset is a planned future addition to
  the sandbox image, not present yet — don't assume semgrep output here is
  complete.
- **`ast-grep`** — structural sweeps for a specific call shape across the
  whole plugin, e.g. `ast-grep run -p '$WPDB->query($SQL)' -l php` or
  `ast-grep run -p 'current_user_can($CAP)' -l php` to pull every call site
  at once for the guard-verification pass.
- **`gitleaks`/`trufflehog`** — as in the generic baseline, for hardcoded
  API keys/credentials a plugin author left in (license-check endpoints,
  third-party service keys).

## Summary

The bugs that become WordPress plugin CVEs are almost never "unsafe PHP" in
the generic sense — they're a missing or mismatched WordPress-specific
guard on an otherwise-ordinary code path: a `wp_ajax_nopriv_*` action with
no capability check, a `$wpdb->prepare()` that placeholders a column name
instead of a value, a nonce checked against the wrong action string. Find
every entry point, trace it to its sink, and verify the WordPress-specific
guard actually covers that exact path before calling it confirmed —
anything less is exactly the kind of finding that burns credibility on a
real CVE submission.
