# Bagisto 2.4.3 — Vulnerabilities

Independent security research against a self-hosted Bagisto 2.4.3 instance (Docker, default installation). All findings were confirmed through manual testing in a private lab environment. No production systems were tested.

This writeup covers three findings that have since been **patched** in the current release line. A separate reported finding remains unaddressed in the latest version at the time of writing and is intentionally excluded from this document to avoid exposing live deployments.

| Researcher | AzureADTrent |
|---|---|
| Target | Bagisto 2.4.3 (Docker, default install) |
| Reported | 2026-05-05, via the vendor support desk |
| Affected | 2.4.3 |
| Fixed | Findings 2 and 3 fixed in 2.4.5; Finding 1 fixed in 2.4.7 (all verified against source) |

---

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-05-04 | Bagisto 2.4.3 released |
| 2026-05-05 | Reported four findings to the vendor support desk (within ~12 hours of the 2.4.3 release) |
| 2026-05-07 | Vendor acknowledged receipt ("we'll check your reported issue and let you know") |
| 2026-06-01 | Requested a status update |
| 2026-06-02 | Vendor replied: "We are still checking your reported issues. After proper checking, we'll let you know." |
| 2026-06 (later) | Findings 1, 2, and 3 were fixed in a subsequent release. The ticket was closed; the vendor stated the issues had been identified internally. |

Fix versions were verified against source across releases: Findings 2 and 3 (the ACL fail-open chain) were fixed in 2.4.5. Finding 1 (the 2FA bypass) remained present in 2.4.5 and 2.4.6 and was fixed in 2.4.7, three release cycles after it was reported. 2.4.5 shipped with release notes referencing resolved security vulnerabilities and did patch Findings 2 and 3, yet the critical 2FA bypass remained unpatched through both 2.4.5 and 2.4.6.

---

## Findings

| # | Severity | Title | Status (as of 2.4.7) |
|---|----------|-------|----------------------|
| 1 | Critical | 2FA bypass via `GET /admin/two-factor/disable` | Fixed in 2.4.7 |
| 2 | High | ACL fails open on missing route names (Bouncer bypass) | Fixed in 2.4.5 |
| 3 | High | Restricted admin can assign super-admin role | Fixed in 2.4.5 |

(A separate critical finding from the same engagement remains unaddressed in the latest version and is excluded; see note above.)

---

### Finding 1 — 2FA bypass via `GET /admin/two-factor/disable`

**Severity:** Critical
**Affected:** 2.4.3 through 2.4.6 · **Fixed:** 2.4.7

**Description.** The `Bouncer` middleware, which enforces authentication and two-factor verification for admin routes, short-circuited all routes matching `admin.two_factor.*` before performing its 2FA-verification check. The `TwoFactorController` disable action only required `auth('admin')->user()` to be non-null, which is true for any session that completed the password step regardless of whether 2FA verification was completed.

As a result, a single `GET /admin/two-factor/disable` request from a password-authenticated-but-not-2FA-verified session wiped `two_factor_secret`, `two_factor_enabled`, `two_factor_backup_codes`, and `two_factor_verified_at` from the admin record, removing 2FA from the account.

The same bypass applied to the `setup` and `enable` routes. After disabling, an attacker could call `setup` (generating a new TOTP secret bound to the attacker's authenticator) and `enable`, silently re-arming 2FA on the victim's account locked to the attacker's device and surviving a subsequent password reset by the owner.

**Proof of concept.**
1. Log in as an admin with 2FA enabled. The server redirects to `/admin/two-factor/verify`.
2. Without completing verification, send:
   ```
   GET /admin/two-factor/disable HTTP/1.1
   Host: <host>
   Cookie: <session cookie from the password login>
   ```
3. 2FA is disabled on the account.

**Impact.** Any attacker with an admin password bypasses 2FA in one request. Chained with default credentials (a separate reported finding), this enabled unauthenticated takeover of a default-installed instance, with the option to lock out the legitimate owner.

**Fix.** In the current release the `Bouncer` middleware allowlist for the pre-verification bypass is restricted to `admin.two_factor.setup`, `admin.two_factor.verify.form`, and `admin.two_factor.verify.store` only. The `disable` and `enable` routes now sit behind the verification check. The fix carries an in-code comment stating that "every other two-factor action — in particular disabling 2FA — must stay behind the verification check, so that a session which has logged in with the password but has not passed two-factor verification cannot use it to switch two-factor authentication off and bypass it."

---

### Finding 2 — ACL fails open on missing route names (Bouncer bypass)

**Severity:** High
**Affected:** 2.4.3 · **Fixed:** 2.4.5

**Description.** Bagisto's admin access control is enforced by the `Bouncer` middleware, which authorizes a request by looking up the current route name in the ACL configuration (`acl.php`). When a route name is absent from that configuration, the permission check is not invoked and the request is allowed. The control fails open rather than closed.

In 2.4.3 a number of state-changing admin route names were absent from `acl.php`, including user-management and role-management routes. Any authenticated admin, regardless of assigned permissions, could reach those routes.

**Proof of concept.**
1. Create an admin role with only `Dashboard` permission.
2. Create an admin user assigned to that restricted role.
3. Log in as the restricted admin.
4. Send a state-changing request to a route absent from `acl.php`, for example updating another admin user:
   ```
   POST /admin/settings/users/edit HTTP/1.1
   Host: <host>
   Cookie: <restricted admin session>
   Content-Type: multipart/form-data

   id=3&name=user&email=user@example.com&role_id=1&status=1&_method=put
   ```
   The update succeeds (`HTTP 200`, "User updated successfully"), including assignment to `role_id=1` (super-admin), despite the caller holding only dashboard permission.

**Impact.** Any admin with any non-empty permission set could execute state-changing operations on routes missing from the ACL, directly enabling Finding 3.

**Fix.** The current release adds the previously-missing route names (including `admin.settings.users.update`, `admin.settings.roles.store`, and related routes) to `acl.php`, so the demonstrated routes are now permission-checked. (Note: the underlying middleware still authorizes by ACL lookup; the fix closes the specific reachable routes rather than changing the fail-open behavior of the lookup itself.)

---

### Finding 3 — Restricted admin can assign super-admin role

**Severity:** High
**Affected:** 2.4.3 · **Fixed:** 2.4.5

**Description.** Building on Finding 2, a restricted admin could escalate to super-admin:
1. The `admin.settings.roles.store` route was missing from `acl.php`, so any authenticated admin could `POST /admin/settings/roles` to create a role with `permission_type=all` (full super-admin permissions). The only validation on `permission_type` was `required|in:all,custom`, so any caller could request `all`.
2. The `admin.settings.users.update` route was also missing, so the same admin could assign the new super-admin role to their own account. The "last super-admin" guard in the user-update logic only prevented demotions, not promotions.

**Proof of concept.** As shown in Finding 2, a restricted admin assigned `role_id=1` (super-admin) to an account. The same approach creates a new `permission_type=all` role via `POST /admin/settings/roles` and assigns it to the attacker's own account.

**Impact.** Any admin with minimal permissions could reach full super-admin access in two requests, defeating the role-based access control model.

**Fix.** Addressed by the same `acl.php` coverage change as Finding 2; the role-create and user-update routes are now permission-checked.

---

## Notes

Findings were reported privately and are published here only after the corresponding fixes shipped. Severity ratings reflect the default-installation context in which they were tested. Line numbers and route names reference the reviewed 2.4.3 source and the 2.4.7 source used to confirm the fixes.
