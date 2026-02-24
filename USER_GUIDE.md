# Wildkat Tracker — User Guide

This guide covers the registration mode web interface at `/manage`. It is intended for both regular users and administrators.

---

## Table of Contents

1. [Roles and Permissions](#1-roles-and-permissions)
2. [Logging In and Registration](#2-logging-in-and-registration)
3. [The Dashboard](#3-the-dashboard)
4. [Registering Torrents](#4-registering-torrents)
5. [Torrent Detail Pages](#5-torrent-detail-pages)
6. [Your Profile](#6-your-profile)
7. [User Profiles](#7-user-profiles)
8. [Searching Torrents](#8-searching-torrents)
9. [Admin Panel](#9-admin-panel)
10. [User Management (Admin)](#10-user-management-admin)
11. [IP Allowlist and IP Lock](#11-ip-allowlist-and-ip-lock)
12. [Settings (Admin)](#12-settings-admin)
13. [Invite Codes](#13-invite-codes)
14. [Passwords](#14-passwords)

---

## 1. Roles and Permissions

Every account has one of four roles. Your role badge is shown next to your username in the navigation bar.

| Role | Badge | Description |
|------|-------|-------------|
| **Basic** | green BASIC | Starting role. Can upload torrents and manage your own dashboard. Cannot view other users' profiles. |
| **Standard** | grey STANDARD | Can view public profiles and torrent lists of other users. |
| **Admin** | orange ADMIN | Full access to the Admin Panel. Can manage users, view all torrents, change settings, generate invite codes. Cannot manage other admins or the superuser. |
| **Super** | blue SUPER | The superuser. Single account with unrestricted access. Cannot be deleted, locked, or demoted. |

Role promotions flow upward — Basic → Standard → Admin. The superuser account is fixed and cannot be changed through the interface.

**Auto-promotion:** If enabled by an admin, Basic users are automatically promoted to Standard once they have registered a certain number of torrents. The threshold is configurable.

---

## 2. Logging In and Registration

### Logging In

Visit `https://your-tracker-domain/manage`. Enter your username and password and click **Login**. Sessions last 48 hours. If you close the browser the session cookie remains until it expires.

Sessions are HTTPS-only — the cookie cannot be sent over plain HTTP.

### Registering an Account

There are three ways to get an account:

**Free Signup** — if the admin has enabled free signup, a **Register** link appears on the login page. Fill in a username and password that meets the site's password requirements.

**Invite Link** — if someone sends you an invite URL (e.g. `https://tracker.example.net/manage/invite/abc123...`), opening it takes you directly to a registration form pre-associated with their invite. The invite is single-use and expires once consumed. You will see who invited you on the registration page.

**Admin-created account** — an admin or superuser creates your account and provides your initial credentials. You can change your password after first login.

### Password Requirements

Password requirements are set by the admin and displayed on the registration and password-change forms. The exact rules are shown in the form itself.

---

## 3. The Dashboard

The Dashboard is your home page after login. It shows all of **your** registered torrents and the upload form.

From the Dashboard you can:

- **Register new torrents** — upload one or more `.torrent` files
- **Copy magnet links** — click the Magnet button on any row
- **Delete your torrents** — shown only if you are the Superuser; otherwise use your Profile page
- **Filter the current page** — type in the filter box to narrow the visible list by name
- **Navigate pages** — pagination controls appear below the table when there are more torrents than fit on one page
- **⚙ Admin Panel** — visible to Admin and Super only
- **🔍 Search** — site-wide torrent search

---

## 4. Registering Torrents

### Uploading a Torrent File

On the Dashboard, use the **Register a Torrent** form. Click **Choose files** and select one or more `.torrent` files, then click **Register**. Bulk uploads of hundreds of files at once are supported.

The tracker extracts the following from each file at upload time:

- Info hash (SHA-1 of the `info` dictionary)
- Torrent name
- Total size
- File list with individual file paths and sizes
- Piece length and piece count
- Private flag

### Duplicate Handling

If a torrent with the same info hash is already registered the upload is silently skipped and reported as "skipped (already registered)".

### Multi-file Uploads

You can select and upload multiple `.torrent` files at once. The result summary shows how many were registered, how many were skipped, and if any failed to parse.

---

## 5. Torrent Detail Pages

Click any torrent name in any listing to open its detail page.

The detail page shows:

- **Name** — the torrent's display name from the `.torrent` file
- **Info Hash** — the full SHA-1 info hash in uppercase hex
- **Type** — Single-file or Multi-file
- **Total Size** — human-readable (B / KB / MB / GB)
- **Piece Size** — size of each piece
- **Piece Count** — number of pieces
- **Private** — whether the torrent's private flag was set
- **Registered By** — the user who uploaded it (clickable link to their profile)
- **Registered At** — date and time of registration

Below the info card is the **file list** — every file in the torrent with its exact size.

The **Copy Magnet Link** button builds a magnet URI from the info hash, torrent name, total size, and the active tracker URLs configured in the Admin Panel.

The **Delete** button appears if you own the torrent or are an Admin/Super.

---

## 6. Your Profile

Click your **username** in the top navigation bar to go to your profile page.

Your profile shows:

- Your role badge
- **Account Details** — join date, created-by (shows "Invited by username" if you joined via invite), login count, last login, last password change, failed attempts, and your current **Credits** balance
- Login history (Superuser view only)
- IP Allowlist — if your account has IP-locking enabled
- **Invite Codes** — your pending and consumed invite codes (see below)
- All your registered torrents with pagination
- **Danger Zone** — delete all your torrents at once (permanent)

From your profile you can also:

- **Change your password** — via the Change Password button
- **Delete individual torrents** — click Delete on any torrent row

### Credits and Invite Generation

If the reward system is enabled, you earn credits by uploading torrents. Once you reach the configured threshold (e.g. every 200 uploads) you receive 1 credit. Credits accumulate — at 400 uploads you have 2, at 600 you have 3, and so on.

Your current credit balance is shown in the **Account Details** card on your profile.

The **Invite Codes** card on your profile always shows your invite history. If you have credits available, a **Generate Invite Link** button appears showing your remaining balance. Clicking it spends 1 credit and creates a new invite code. If you have no credits the button is visible but disabled.

Each invite code in the list has a **Copy URL** button — click it to copy the full invite link to your clipboard. Share this URL with the person you want to invite. Once they register with it the code is marked consumed and the entry shows who used it.

---

## 7. User Profiles

Standard, Admin, and Super users can view public profiles of other users by clicking their username in any torrent listing or by navigating to `/manage/user/{username}`.

A public profile shows:

- The user's role badge
- Join date
- Total torrent count
- Their full paginated torrent list

**What is not shown** on a public profile: login count, last login, failed login attempts, created-by, credits, password history, IP addresses, or any administrative controls.

Basic users are redirected to their dashboard if they attempt to view a profile.

If you are an Admin or Super, a small **⚙ Admin View** link appears on the public profile page that takes you directly to the full administrative view of that user.

---

## 8. Searching Torrents

Click the **🔍 Search** button on the Dashboard or navigate to `/manage/search`.

The search engine splits your query into individual tokens and matches each one independently. Dots, dashes, and underscores in torrent names are treated as spaces, so you can search naturally:

- `ubuntu 24` matches `ubuntu-24.04.2-live-server-amd64.iso`
- `ubuntu 24 server` also matches — all three tokens must be present
- `ubuntu 24 desktop` does not match — `desktop` is not in the name
- You can also search by exact dotted name: `ubuntu-24.04.2` splits into tokens the same way
- Searching by info hash fragment also works

All tokens must match for a result to appear (AND logic). The search is case-insensitive.

Basic users see only their own torrents in search results. Standard and above see all torrents on the tracker.

An additional **Filter this page** box on the results page lets you narrow the current page instantly without a new search.

---

## 9. Admin Panel

Accessible to Admin and Super only via the **⚙ Admin Panel** button on the Dashboard.

The Admin Panel has seven tabs:

### Torrents Tab

All registered torrents across all users, paginated. Includes the owner column. Admins and Super can delete any torrent from this view.

### Users Tab

All registered accounts. Shows each user's role badges, creation date, login count, and last login. Click a username to go to the full user management page for that account.

### Add User Tab

Create a new account directly by specifying username, password, and role. Use this when you want to create an account without sending an invite link.

### Trackers Tab

Manage the tracker URLs embedded in generated magnet links. Each tracker can be enabled or disabled individually. You can also add new tracker URLs or remove existing ones.

### Settings Tab

See [Section 12](#12-settings-admin) below.

### Invites Tab

See [Section 13](#13-invite-codes) below. Visible to Admin and Super.

### Danger Tab

See the Danger Zone operations in [Section 10](#10-user-management-admin). Visible to Super only.

### Event Log Tab

A log of significant actions — user creation, torrent registration, deletions, password changes, IP lock operations, settings changes, credit adjustments, invite creation and consumption, and more. Each event shows a timestamp, the actor who performed it, and a description. The 100 most recent events are shown.

---

## 10. User Management (Admin)

Click any username in the Users tab to open their management page.

### Account Information

Shows all account fields including join date, created-by (displayed as "Invited by **username**" when the account was created via invite), last login, login count, failed attempts, last password change, and current credits balance.

### Role Management

Admins can promote or demote Standard and Basic users. Superusers can also promote/demote Admin accounts. No one can change the Superuser account's role.

### Locking and Disabling

- **Locked** — set automatically after 5 consecutive failed login attempts. Cannot log in until an admin clicks **Unlock Account**. The failed attempts counter resets when the password is changed or the account is unlocked.
- **Disable / Enable** — a manual block that admins can toggle at any time. A disabled account cannot log in.

### Password Reset

Admins can set a new password for any account below their own role level.

### Credit Adjustment

The **Actions** card includes **+ Credit** and **− Credit** buttons. Use these to manually add or remove credits from a user's balance. The balance is floored at zero. All adjustments are logged in the Event Log.

### IP Allowlist

See [Section 11](#11-ip-allowlist-and-ip-lock) below.

### Torrent List

All torrents registered by this user, paginated. Admins and Super can delete individual torrents.

### Danger Zone

Permanently deletes all torrents registered by this user in a single operation. Only visible to the Superuser, or to the user on their own profile. Shows an accurate total count before confirmation.

---

## 11. IP Allowlist and IP Lock

The IP allowlist restricts a user account to only log in from specific IP addresses.

### Building the Allowlist from Login History

On any user's management page, the **Recent Login IPs** card shows IP addresses from that user's recent logins with timestamps and checkboxes.

To add one or more IPs to the allowlist:

1. Check the boxes next to the IPs you want to allow
2. Click **🔒 IP Lock Selected**

### Manual Entry

You can also manually add any IP address by typing it into the input field and clicking **Add**.

### Removing Entries

Click **Remove** next to any entry to remove it. Click **Clear All** to remove all entries and disable IP locking for that account.

### IPv6 Addresses

Full IPv6 addresses are supported. IPv4 and IPv6 addresses are treated separately.

---

## 12. Settings (Admin)

The **Settings** tab controls site-wide behaviour. All changes take effect immediately without restarting the server.

### Password Complexity

Controls what passwords are accepted: minimum length (default: 12), require uppercase, require lowercase, require digit, require symbol. These rules apply to registration, admin-set passwords, and self-service password changes.

### Open Tracker

When **on**, the tracker accepts BitTorrent announces for any info hash — not just torrents registered in the database. User accounts and the web interface are unaffected. Useful for running a semi-open tracker while still managing user access to the web interface. Default: off.

### Free Signup

When **on**, anyone can register a new account via the login page. When **off**, new users can only join via invite link or admin-created account. Default: off.

### Reward System

When **on**, users automatically earn 1 credit for every N torrents they upload. The threshold N is configurable (default: 200). Credits are recurring — a user earns a credit at 200 uploads, another at 400, another at 600, and so on. Credits can be spent to generate invite links. Default: off.

### Torrents Per Page

Controls how many torrents are shown per page on the Dashboard, Admin Panel, user profiles, and search results. Range: 5 to 500. Default: 50.

### Auto-Promote

When **on**, Basic users are automatically promoted to Standard when they have registered at least the configured number of torrents. The threshold is configurable (default: 25 torrents).

### robots.txt

The content returned at `/robots.txt`. By default, search engine crawlers are told to stay away from `/announce`, `/scrape`, and `/manage`. Edit here if you want different behaviour.

---

## 13. Invite Codes

Invite codes allow controlled onboarding of new users without enabling open free signup.

### Admin — Invites Tab

The **Invites** tab in the Admin Panel (visible to Admin and Super) shows a table of all invite codes across all users:

| Column | Description |
|--------|-------------|
| Code | Truncated token — enough to identify it |
| Created By | The admin or user who generated it — clickable link to their profile |
| Created At | When it was created |
| Status | **Pending** (unused) or **Used by username** with date — username is a clickable link |
| Actions | Copy URL button and Delete button (pending codes only) |

To generate a new invite code as an admin, click **+ Generate Invite Code** at the top of the tab. The code appears in the table immediately. Use the **Copy URL** button to get the full invite link to share.

To revoke an unused code, click **Delete** on its row.

### User — Generating Invites with Credits

If the reward system is enabled and you have credits, the **Invite Codes** card on your profile shows a **Generate Invite Link** button with your remaining balance. Clicking it spends 1 credit and creates a new invite code.

If you have no credits the button is shown disabled — it does nothing when clicked. Credits are earned by uploading torrents once the reward system is enabled by an admin.

Your invite history is always visible in the Invite Codes card regardless of your current credit balance, so you can see which of your past invites have been used and by whom.

### The Invite Link

An invite URL looks like:

```
https://tracker.example.net/manage/invite/abc123def456...
```

Opening this URL shows a registration form with a note showing who invited you. The invite is single-use — once someone completes registration with it, the code is consumed and cannot be reused. If the link has already been used or deleted, an "Invalid Invite" page is shown.

Accounts created via invite show "Invited by **username**" in their Account Details rather than a plain created-by value.

---

## 14. Passwords

### Changing Your Own Password

From your profile page, click **Change Password**. Enter your current password and the new password twice to confirm. The new password must meet the site's complexity requirements.

### Forgotten Password / Lockout

There is no self-service password reset — contact an admin or superuser. They can set a new password for your account from the user management page.

If the **superuser** is locked out, the password must be reset from the command line on the server (see INSTALL.md section 8.5).

### Password Security

Passwords are hashed using PBKDF2-HMAC-SHA256 with 260,000 iterations and a unique random salt per account. Plain-text passwords are never stored or logged. Session tokens are cryptographically random 32-byte hex strings stored only in the browser cookie and the database (never logged).
