# Wildkat Tracker — User Guide

This guide covers the registration mode web interface at `/manage`. It is intended for both regular users and administrators.

---

## Table of Contents

1. [Roles and Permissions](#1-roles-and-permissions)
2. [Logging In and Registration](#2-logging-in-and-registration)
3. [The Dashboard](#3-the-dashboard)
4. [Registering Torrents](#4-registering-torrents)
5. [Torrent Detail Pages](#5-torrent-detail-pages)
6. [Comments and Notifications](#6-comments-and-notifications)
7. [Your Profile](#7-your-profile)
8. [User Profiles](#8-user-profiles)
9. [Searching Torrents](#9-searching-torrents)
10. [Admin Panel](#10-admin-panel)
11. [User Management (Admin)](#11-user-management-admin)
12. [IP Allowlist and IP Lock](#12-ip-allowlist-and-ip-lock)
13. [Settings (Admin)](#13-settings-admin)
14. [Invite Codes](#14-invite-codes)
15. [Database Backup and Restore](#15-database-backup-and-restore)
16. [Passwords](#16-passwords)

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

Password requirements are set by the admin and displayed on the registration and password-change forms. The exact rules are shown in the form itself. All password fields include a **show/hide eye button** — click it to reveal what you are typing to confirm there are no typos.

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

If comments are enabled site-wide, a **Comments** section appears below the file list. See [Section 6](#6-comments-and-notifications).

---

## 6. Comments and Notifications

Comments can be left on any torrent detail page when the feature is enabled by an administrator. If comments are disabled site-wide, the comments section and the notification bell are hidden entirely — there is no visible trace of the system.

### Posting a Comment

Type your comment in the text area at the bottom of the torrent detail page and click **Post Comment**. Comments support **@mentions** — type `@username` anywhere in your text to notify that user.

- You can only mention users who exist on the tracker. If you mention a username that does not exist, the comment is still posted but a modal alert appears warning you which @mentions were not delivered.
- You cannot mention yourself.

### Replies

Click **Reply** on any comment to post a threaded reply. Replies are visually indented below their parent comment. Threading is recursive — you can reply to replies. Each level is indented to show the hierarchy.

### Editing Comments

Click **Edit** on one of your own comments to modify it. The edit box replaces the comment inline. @mention validation runs on edits as well — unknown mentions trigger the same modal warning.

### Deleting Comments

Click **Delete** on one of your own comments. If the comment has no replies it is removed immediately. If it has replies, a `[deleted]` placeholder is shown in its place to preserve the thread structure.

Admins and Super can delete any comment regardless of ownership.

### Comment Locking

Admins and Super can **lock** comments on any torrent. When locked, no new comments or replies can be posted by anyone. A lock badge appears in the comment section header. Existing comments remain visible. Locking and unlocking is toggled from the **Actions** card on the torrent detail page.

### Deleting All Comments on a Torrent

Admins and Super have a **🗑 Delete All Comments** button in the Actions card on the torrent detail page. This permanently removes every comment and notification associated with that torrent. This cannot be undone.

### The Notification Bell

When someone replies to your comment or @mentions you, a notification is created and the 🔔 bell icon in the navigation bar shows a count badge.

**Bell dropdown** — click the bell to see your 5 most recent unread notifications. Each item shows who acted, what they did, and which torrent it was on. Click any item to mark it read and jump to the comment. A **View all notifications** link at the bottom opens the full page.

**Notifications page** (`/manage/notifications`) — shows all your notifications, read and unread. Unread items are highlighted. Click the torrent name or the **View →** button on any row to mark it read and navigate to the comment. Use **✓ Mark all read** to clear everything at once.

The bell is hidden from the navigation bar when the comments and notifications system is disabled by an administrator.

---

## 7. Your Profile

Click your **username** in the top navigation bar to go to your profile page.

Your profile shows:

- Your role badge and status badges (locked, disabled) if applicable
- **Account Details** — join date, created-by (shows "Invited by username" if you joined via invite), login count, last login, last password change, failed attempts, and your current **Credits** balance
- **Actions card** — contains a **Change Password** button that takes you to the password change page
- Login history (Superuser view only)
- IP Allowlist — if your account has IP-locking enabled
- **Invite Codes** — your pending and consumed invite codes
- All your registered torrents with pagination
- **Danger Zone** — delete all your torrents at once (permanent)

### Credits and Invite Generation

If the reward system is enabled, you earn credits by uploading torrents. Once you reach the configured threshold (e.g. every 200 uploads) you receive 1 credit. Credits accumulate — at 400 uploads you have 2, at 600 you have 3, and so on.

Your current credit balance is shown in the **Account Details** card on your profile.

The **Invite Codes** card shows your invite history. If you have credits available, a **Generate Invite Link** button appears. Clicking it spends 1 credit and creates a new invite code. If you have no credits the button is shown disabled.

Each invite code in the list has a **Copy URL** button to copy the full invite link to your clipboard. Once someone registers with it the code is marked consumed and the entry shows who used it.

---

## 8. User Profiles

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

## 9. Searching Torrents

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

## 10. Admin Panel

Accessible to Admin and Super only via the **⚙ Admin Panel** button on the Dashboard.

The Admin Panel has nine tabs:

### Torrents Tab

All registered torrents across all users, paginated. Includes the owner column. Admins and Super can delete any torrent from this view.

### Users Tab

All registered accounts with role badges, creation date, login count, and last login. Click a username to open their full management page. Each row includes a **Set Password** button that opens the dedicated password-change page for that user.

### Add User Tab

Create a new account by specifying username, password, and role (Basic, Standard, or Admin). Use this when you want to create an account without sending an invite link.

If the password does not meet the site's complexity requirements, an error message explains exactly which rules failed. The tab stays open and the username you typed is pre-filled so you only need to correct the password.

### Trackers Tab

Manage the tracker URLs embedded in generated magnet links. Each tracker can be individually enabled or disabled. Add new tracker URLs or remove existing ones.

### Settings Tab

See [Section 13](#13-settings-admin).

### Database Tab

See [Section 15](#15-database-backup-and-restore). Visible to Super only.

### Invites Tab

See [Section 14](#14-invite-codes). Visible to Admin and Super.

### Danger Tab

See [Section 11](#11-user-management-admin) — Super-Only Danger Operations. Visible to Super only.

### Event Log Tab

A log of significant actions — user creation, torrent registration, deletions, password changes, IP lock operations, settings changes, credit adjustments, invite creation and consumption, comment actions, database backup and restore, and system wipe. Each entry shows a timestamp, the actor who performed it, and a description. The 100 most recent events are shown.

---

## 11. User Management (Admin)

Click any username in the Users tab to open their management page.

### Account Information

Shows all account fields: join date, created-by (displayed as "Invited by **username**" when the account was created via invite), last login, login count, failed attempts, last password change, and current credits balance.

### Actions Card

The **Actions** card contains all controls for that account:

- **Set Password** — opens the dedicated password-change page for this user
- **Unlock Account** — appears only when the account is locked after failed login attempts
- **Disable / Enable** — manually block or unblock an account
- **Promote / Demote** — role management buttons
- **Delete User** — permanently removes the account
- **+ Credit / − Credit** — manually adjust the user's credit balance

### Role Management

Admins can promote or demote Standard and Basic users. Superusers can also promote/demote Admin accounts. No one can change the Superuser account's role.

### Locking and Disabling

- **Locked** — set automatically after 5 consecutive failed login attempts. An admin must click **Unlock Account** to restore access. The failed attempts counter resets on unlock or password change.
- **Disable / Enable** — a manual block admins can toggle at any time. A disabled account cannot log in regardless of password.

### IP Allowlist

See [Section 12](#12-ip-allowlist-and-ip-lock).

### Torrent List

All torrents registered by this user, paginated. Admins and Super can delete individual torrents.

### Danger Zone

Permanently deletes all torrents registered by this user in a single operation. Only visible to the Superuser, or to the user themselves on their own profile. Shows an accurate count before the confirmation prompt.

### Super-Only Danger Operations

The **Danger** tab in the Admin Panel contains four operations, only accessible to the Superuser:

- **Delete All Users** — permanently deletes every account except the super account. All sessions are invalidated.
- **Delete All Torrents** — permanently removes every registered torrent from the tracker.
- **Delete All Comments & Notifications** — permanently removes every comment and notification across the entire system. Torrent lock states are preserved.
- **☢ System Wipe** — wipes all users (except the super account), all torrents, all comments, all notifications, all invite codes, all sessions, and the entire event log. Returns the tracker to near-factory state.

The System Wipe requires a two-step typed confirmation to prevent accidents:

1. A modal asks you to type `SYSTEMWIPE` exactly — the Continue button stays disabled until the text matches precisely.
2. A second modal gives you one final chance to cancel before anything is deleted.

---

## 12. IP Allowlist and IP Lock

The IP allowlist restricts an account to only log in from specific IP addresses.

### Building the Allowlist from Login History

On a user's management page, the **Recent Login IPs** card shows IP addresses from their recent logins with timestamps and checkboxes.

1. Check the boxes next to the IPs you want to allow
2. Click **🔒 IP Lock Selected**

### Manual Entry

Type any IP address into the input field and click **Add** to add it directly without requiring a prior login from that address.

### Removing Entries

Click **Remove** next to any entry to remove it individually. Click **Clear All** to remove all entries and disable IP locking for that account.

### IPv6 Addresses

Full IPv6 addresses are supported. IPv4 and IPv6 addresses are treated separately.

---

## 13. Settings (Admin)

The **Settings** tab controls site-wide behaviour. All changes take effect immediately without restarting the server.

### Password Complexity

Controls what passwords are accepted: minimum length (default: 12), require uppercase, require lowercase, require digit, require symbol. These rules apply to registration, admin-set passwords, and self-service password changes.

### Open Tracker

When **on**, the tracker accepts BitTorrent announces for any info hash — not just torrents registered in the database. User accounts and the web interface are unaffected. Default: off.

### Reward System

When **on**, users automatically earn 1 credit for every N torrents they upload. The threshold N is configurable (default: 200). Credits accumulate and can be spent to generate invite links. Default: off.

### Free Signup

When **on**, anyone can register a new account via the login page without an invite. Default: off.

### Torrents Per Page

Controls how many torrents are shown per page on the Dashboard, Admin Panel, user profiles, and search results. Range: 5 to 500. Default: 50.

### Auto-Promote

When **on**, Basic users are automatically promoted to Standard once they have registered at least the configured number of torrents. Default threshold: 25 torrents.

### Comments & Notifications

When **on**, the full comment and notification system is active on all torrent detail pages and the notification bell appears in the navigation bar. When **off**, the comments section is completely removed from all torrent pages and the bell disappears from the navbar. Default: on.

### robots.txt

The content returned at `/robots.txt`. By default, search engine crawlers are instructed to avoid `/announce`, `/scrape`, and `/manage`. Edit here to change crawl behaviour.

---

## 14. Invite Codes

Invite codes allow controlled onboarding of new users without enabling open free signup.

### Admin — Invites Tab

The **Invites** tab (visible to Admin and Super) shows all invite codes across all users:

| Column | Description |
|--------|-------------|
| Code | Truncated token |
| Created By | Who generated it — clickable link |
| Created At | When it was created |
| Status | **Pending** or **Used by username** with date — username is a link |
| Actions | Copy URL and Delete (pending only) |

Click **+ Generate Invite Code** to create a new code. Use **Copy URL** to get the shareable link. Click **Delete** to revoke an unused code.

### User — Generating Invites with Credits

If the reward system is enabled and you have credits, the **Invite Codes** card on your profile shows a **Generate Invite Link** button. Clicking it spends 1 credit and creates a new code. With no credits the button is shown but disabled.

Your invite history is always visible regardless of credit balance — you can always see which invites you have generated and who consumed them.

### The Invite Link

```
https://tracker.example.net/manage/invite/abc123def456...
```

Opening the URL shows a registration form noting who invited you. The link is single-use — once someone registers with it the code is consumed and cannot be reused. An "Invalid Invite" page is shown if the link has expired or been deleted.

Accounts created via invite show "Invited by **username**" in their Account Details.

---

## 15. Database Backup and Restore

The **Database** tab in the Admin Panel (Super only) provides live backup and restore without downtime.

### Creating a Backup

Click **⬇ Download Backup**. The server creates a consistent snapshot using SQLite's online backup API and downloads it as:

```
tracker-backup-YYYYMMDD-HHMMSS.db.gz
```

The current database size is shown on the card. The download is logged in the Event Log.

### Restoring from a Backup

Click **⬆ Restore from Backup**, choose a `.db.gz` file, and confirm. Before touching the live database the server:

1. Confirms the file is valid gzip
2. Confirms the decompressed content is a real SQLite database
3. Runs an integrity check on the backup

If all checks pass, the live database file is replaced on disk, WAL and SHM sidecar files are cleared, and all active connections across all server threads reopen automatically. You are redirected to the Database tab with a success message.

> **Important:** Take a fresh backup before restoring. The restore overwrites all current data immediately and cannot be undone.

---

## 16. Passwords

### Showing and Hiding Password Input

All password fields on the site include an **eye button** (👁) on the right edge of the input. Click it to reveal what you are typing in plain text — useful for confirming there are no typos before submitting. Click again to hide. The button does not affect keyboard tab order and cannot accidentally submit the form.

This applies to: the invite and free signup forms, the Change Password page, the Set Password (admin) page, and the Add User form in the Admin Panel.

### Changing Your Own Password

From your profile page, click **Change Password**. Enter your current password and the new password twice to confirm. The new password must meet the site's complexity requirements, which are displayed on the form. On success you are returned to the Dashboard.

### Admin Setting Another User's Password

From a user's management page (Actions card) or the Users tab in the Admin Panel, click **Set Password**. This opens a dedicated page — *Set Password — Changing password for [username]* — where you enter the new password twice. No knowledge of the user's current password is required. The same complexity requirements apply and are shown on the form.

All password changes are logged in the Event Log with the actor and the target account.

### Forgotten Password / Lockout

There is no self-service password reset — contact an admin or superuser. They can set a new password from the user management page without needing to know the current password.

If the **superuser** is locked out, the password must be reset from the command line on the server (see INSTALL.md).

### Password Security

Passwords are hashed using PBKDF2-HMAC-SHA256 with 260,000 iterations and a unique random salt per account. Plain-text passwords are never stored or logged. Session tokens are cryptographically random 32-byte hex strings stored only in the browser cookie and the database — never logged anywhere.
