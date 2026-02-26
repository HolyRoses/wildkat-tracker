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
10. [Points Economy](#10-points-economy)
11. [Bounty Board](#11-bounty-board)
12. [Leaderboard](#12-leaderboard)
13. [Admin Panel](#13-admin-panel)
14. [User Management (Admin)](#14-user-management-admin)
15. [IP Allowlist and IP Lock](#15-ip-allowlist-and-ip-lock)
16. [Settings (Admin)](#16-settings-admin)
17. [Economy Settings (Admin)](#17-economy-settings-admin)
18. [Invite Codes](#18-invite-codes)
19. [Database Backup and Restore](#19-database-backup-and-restore)
20. [Passwords](#20-passwords)

---

## 1. Roles and Permissions

Every account has one of four roles. Your role badge is shown next to your username in the navigation bar.

| Role | Badge | Description |
|------|-------|-------------|
| **Basic** | green BASIC | Starting role. Can upload torrents and manage your own dashboard. Cannot view other users' profiles, access the Bounty Board, or see the Leaderboard. |
| **Standard** | grey STANDARD | Can view public profiles and torrent lists of other users. Full access to the Bounty Board, point transfers, and Leaderboard. |
| **Admin** | orange ADMIN | Full access to the Admin Panel. Can manage users, view all torrents, change settings, generate invite codes. Cannot manage other admins or the superuser. |
| **Super** | blue SUPER | The superuser. Single account with unrestricted access. Cannot be deleted, locked, or demoted. |

Role promotions flow upward — Basic → Standard → Admin. The superuser account is fixed and cannot be changed through the interface.

**Auto-promotion:** If enabled by an admin, Basic users are automatically promoted to Standard once they have uploaded a configured number of torrents. The threshold is configurable.

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

Password requirements are set by the admin and displayed on the registration and password-change forms. All password fields include a **show/hide eye button** — click it to reveal what you are typing to confirm there are no typos.

---

## 3. The Dashboard

The Dashboard is your home page after login. It shows all of **your** registered torrents and the upload form.

From the Dashboard you can:

- **Register new torrents** — upload one or more `.torrent` files
- **Copy magnet links** — click the Magnet button on any row
- **Delete your torrents** — shown only on the torrent's detail page
- **Filter the current page** — type in the filter box to narrow the visible list by name
- **Navigate pages** — pagination controls appear when there are more torrents than fit on one page

The **navigation bar** runs across the top of every page with three zones: the 🐈 WILDKAT logo on the left, center navigation buttons (🖥 Dashboard, 🔍 Search, 🎯 Bounties, 🏆 Leaderboard), and your username/badge, notification bell, and logout on the right. The Bounties and Leaderboard buttons are hidden for Basic users.

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

- **Name** — the torrent's display name
- **Info Hash** — the full SHA-1 info hash. Click it to copy to clipboard instantly; the text flashes ✓ Copied in green for confirmation
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

> **Tip:** The click-to-copy info hash is especially useful when filling out a Bounty claim — copy the hash directly from the torrent page rather than selecting and right-clicking.

If comments are enabled site-wide, a **Comments** section appears below the file list. See [Section 6](#6-comments-and-notifications).

---

## 6. Comments and Notifications

Comments can be left on any torrent detail page when the feature is enabled by an administrator.

### Posting a Comment

Type your comment in the text area and click **Post Comment**. Comments support **@mentions** — type `@username` anywhere in your text to notify that user.

### Replies, Editing, and Deleting

Click **Reply** on any comment to post a threaded reply. Replies are visually indented and threading is recursive. Click **Edit** on one of your own comments to modify it inline. Click **Delete** to remove it — if the comment has replies a `[deleted]` placeholder is shown to preserve thread structure.

Admins and Super can delete any comment regardless of ownership, and have a **🗑 Delete All Comments** button in the torrent Actions card.

### Comment Locking

Admins and Super can **lock** comments on a torrent from the Actions card. When locked no new comments can be posted. A lock badge appears in the section header.

### The Notification Bell

When someone replies to your comment, @mentions you, or bounty events occur (claim, confirmation, rejection, payout), a 🔔 badge appears in the navigation bar.

**Bell dropdown** — click the bell to see your 5 most recent unread notifications. Each item shows who acted, what they did, and which torrent or bounty it relates to. Click any item to mark it read and navigate to the relevant page.

**Notifications page** (`/manage/notifications`) — shows all notifications, read and unread. Use **✓ Mark all read** to clear everything at once.

### Bounty Notifications

In addition to comment notifications, the bell delivers bounty-related events:

| Icon | Event |
|------|-------|
| 🎯 | Someone claimed your bounty |
| ✗ | Your claim was rejected |
| ✅ | A bounty you claimed was confirmed |
| ➕ | Someone added points to your bounty |
| ⏰ | Your bounty expired without being fulfilled |
| 💰 | Someone fulfilled a bounty using your upload |

---

## 7. Your Profile

Click your **username** in the top navigation bar to go to your profile page.

Your profile shows:

- Your role badge and status badges (locked, disabled) if applicable
- **Account Details** — join date, created-by (shows "Invited by username" if you joined via invite), login count, last login, last password change, failed attempts, current **Points** balance (color-coded red if negative), and current **Login Streak** if you are on a streak
- **Actions card** — Change Password button
- IP Allowlist — if your account has IP-locking enabled
- **Invite Codes** — your pending and consumed invite codes, and the Purchase Invite Link button if you have enough points
- All your registered torrents with pagination
- **Danger Zone** — delete all your torrents at once (permanent)

### Points and Invite Generation

Your current points balance is shown in the **Account Details** card. Points are earned automatically for daily logins (with streak bonuses), torrent uploads, and comments. See [Section 10](#10-points-economy) for full details.

The **Invite Codes** card shows your invite history. If you have enough points (default 1,000), a **Purchase Invite Link (N pts)** button appears. Clicking it shows a confirmation dialog stating exactly how many points will be spent, then creates a new invite code. If you do not have enough points the button is shown but disabled with the shortfall displayed.

---

## 8. User Profiles

Standard, Admin, and Super users can view public profiles of other users by clicking their username in any listing or navigating to `/manage/user/{username}`.

A public profile shows:

- The user's role badge
- Member Since date
- **Points** balance (color-coded)
- **Login Streak** (if active)
- Total torrent count
- Their full paginated torrent list

**What is not shown** on a public profile: login count, last login, failed login attempts, created-by, password history, IP addresses, or any administrative controls.

Basic users are redirected to their dashboard if they attempt to view a profile.

If you are an Admin or Super, a small **⚙ Admin View** link appears on the public profile page that takes you directly to the full administrative view of that user.

---

## 9. Searching Torrents

Click the **🔍 Search** button in the navigation bar or navigate to `/manage/search`.

The search engine splits your query into individual tokens and matches each one independently. Dots, dashes, and underscores in torrent names are treated as spaces, so you can search naturally:

- `ubuntu 24` matches `ubuntu-24.04.2-live-server-amd64.iso`
- `ubuntu 24 server` also matches — all three tokens must be present
- `ubuntu 24 desktop` does not match — `desktop` is not in the name
- Searching by info hash fragment also works

All tokens must match (AND logic). The search is case-insensitive.

Basic users see only their own torrents in search results. Standard and above see all torrents on the tracker.

---

## 10. Points Economy

The points system is the site's internal currency. Points are earned, spent, transferred, and destroyed according to rules the admin configures. There is no way to acquire points outside the system.

### Earning Points

| Activity | Points |
|----------|--------|
| Daily login | Configurable base amount (default: 10 pts) |
| Login streak bonus | Multiplier per consecutive day (default: +1 pt/day, up to a cap) |
| Registering a torrent | Configurable per upload (default: 5 pts) |
| Posting a comment | Configurable per comment (default: 2 pts) |

Streaks reset if you miss a day. The current streak is shown on your profile and the leaderboard.

### Spending Points

| Activity | Cost |
|----------|------|
| Purchasing an invite code | 1,000 pts (default, configurable by admin) |
| Creating a bounty | Variable — you set the initial escrow amount |
| Contributing to a bounty | Variable — you choose how much to add |
| Sending points to another user | Amount + transfer fee % |

### Point Transfers

Standard+ users can send points to other users directly from their profile or from the recipient's public profile. A configurable fee percentage is taken and **destroyed** (not redistributed) — this is deflationary by design. The transfer is logged in the event log.

### Negative Balances

Points balances can go negative (shown in red). This happens when a user has spent more than they have earned. Negative-balance users can still use the site normally but cannot make purchases until they return to a positive balance.

---

## 11. Bounty Board

The Bounty Board lets users post point-backed requests for specific content. Navigate to it via the **🎯 Bounties** button in the nav bar (Standard+ only).

### Creating a Bounty

Click **+ Post Bounty**. Fill in a description of what you are looking for and set an initial escrow amount (the points you are committing from your balance). The points are held in escrow immediately — they do not leave until the bounty is fulfilled, expired, or refunded.

### Contributing to a Bounty

Any Standard+ user — including the requestor — can add more points to any open or pending bounty. This raises the prize to attract fulfillment. Click **Contribute** on any bounty and enter the amount.

### Claiming a Bounty

If you have a torrent that matches an open bounty, click **Claim** and paste in the info hash. The bounty moves to **Pending** status while the requestor reviews.

> **Tip:** Copy the info hash from the torrent's detail page by clicking on it — it copies to clipboard in one click.

### Confirmation

The requestor receives a notification and can **Confirm** or **Reject** the claim from the bounty detail page.

- **Confirm** — triggers the payout (see below) and marks the bounty Fulfilled
- **Reject** — bounty returns to Open and can be claimed again
- **No action** — after the pending window expires (configurable, default 48 hours), the bounty automatically reopens
- **Community vote** — if enough Standard+ users vote the claim legitimate, it auto-confirms without the requestor

### Payout Breakdown

When a bounty is fulfilled, the escrow is distributed as follows (all percentages configurable):

| Recipient | Description |
|-----------|-------------|
| Claimer | Primary payout — majority of escrow |
| Uploader | Bonus if the claimer used someone else's registered torrent |
| Requestor refund | Partial return of the requestor's initial escrow cost |
| House cut | Percentage destroyed — deflationary |

The fulfilled bounty detail page shows the full breakdown with exact amounts and percentages.

### Bounty Statuses

| Status | Meaning |
|--------|---------|
| Open | Accepting claims |
| Pending | Claim submitted, awaiting confirmation |
| Fulfilled | Confirmed and paid out |
| Expired | Pending window passed with no confirmation; bounty reopened |

---

## 12. Leaderboard

Navigate to **🏆 Leaderboard** in the nav bar (Standard+ only). The leaderboard shows the top N users (configurable by admin, default 10) in six categories.

| Category | Metric |
|----------|--------|
| 💰 Top Holders | Current points balance — who has the most points right now |
| 📈 All-Time Earners | Total points ever earned — spending does not hurt your rank |
| 📦 Top Uploaders | Most torrents registered on the tracker |
| 🎯 Bounty Hunters | Most bounties successfully fulfilled |
| 🔥 Login Streaks | Longest current consecutive daily login streak |
| 💬 Most Chatty | Most comments posted across all torrents |

Top 3 in each category receive 🥇🥈🥉 medals. All usernames link to public profiles. Rankings update in real time.

---

## 13. Admin Panel

Accessible to Admin and Super only via the **⚙ Admin Panel** link (visible on the dashboard for admins).

The Admin Panel has ten tabs:

### Torrents Tab

All registered torrents across all users, paginated. Includes the owner column. Admins and Super can delete any torrent from this view.

### Users Tab

All registered accounts with role badges, creation date, login count, and last login. Click a username to open their full management page. Each row includes a **Set Password** button.

### Add User Tab

Create a new account by specifying username, password, and role (Basic, Standard, or Admin).

### Trackers Tab

Manage the tracker URLs embedded in generated magnet links. Each tracker can be individually enabled or disabled.

### Settings Tab

See [Section 16](#16-settings-admin).

### Database Tab

See [Section 19](#19-database-backup-and-restore). Visible to Super only.

### Economy Tab

See [Section 17](#17-economy-settings-admin). Visible to Super only.

### Invites Tab

See [Section 18](#18-invite-codes). Visible to Admin and Super.

### Danger Tab

Bulk-delete operations and System Wipe. Visible to Super only. See [Section 14](#14-user-management-admin).

### Events Tab

A searchable log of significant actions across the entire system.

**Search fields:**

- **Search all fields** — free text matched across timestamp, actor, action, target, and detail (e.g. type a username to find all events involving them)
- **Actor** — who performed the action
- **Action** — what type of event (e.g. `award_points`, `register_torrent`, `login`, `bounty_fulfill`)
- **Target** — who the action was performed on

Results show total matching count and up to 200 rows, newest first. Rows are color-coded: red for deletions/bans/penalties, green for logins/registrations/awards, amber for bounty and points activity.

Use the **✕ Clear** button to reset all filters and return to the full unfiltered log.

---

## 14. User Management (Admin)

Click any username in the Users tab to open their management page.

### Account Information

Shows all account fields: join date, created-by, last login, login count, failed attempts, last password change, current points balance, and login streak.

### Actions Card

- **Set Password** — opens the dedicated password-change page
- **Unlock Account** — appears only when the account is locked after failed login attempts
- **Disable / Enable** — manually block or unblock an account
- **Promote / Demote** — role management buttons
- **Delete User** — permanently removes the account
- **Point adjustment** — a number input where you type any positive or negative value (positive = grant, negative = remove). Click **＋ Grant** to add points or **－ Remove** to take them away. **Quick +10 / Quick −10** buttons are available for small adjustments. The maximum per transaction is enforced by the admin-configured limit (default 1,000 pts, configurable in the Economy tab)

### Role Management

Admins can promote or demote Standard and Basic users. Superusers can also promote/demote Admin accounts.

### Locking and Disabling

- **Locked** — set automatically after 5 consecutive failed login attempts. An admin must click **Unlock Account** to restore access
- **Disable / Enable** — a manual block admins can toggle at any time

### Super-Only Danger Operations

The **Danger** tab in the Admin Panel contains four operations accessible only to the Superuser:

- **Delete All Users** — permanently deletes every account except the super account. All sessions are invalidated
- **Delete All Torrents** — permanently removes every registered torrent
- **Delete All Comments & Notifications** — removes every comment and notification system-wide
- **☢ System Wipe** — wipes all users (except super), all torrents, all comments, all notifications, all invite codes, all sessions, and the entire event log. Returns the tracker to near-factory state

The System Wipe requires a two-step typed confirmation: first type `SYSTEMWIPE` exactly, then a final confirmation screen.

---

## 15. IP Allowlist and IP Lock

The IP allowlist restricts an account to only log in from specific IP addresses.

### Building the Allowlist from Login History

On a user's management page, the **Recent Login IPs** card shows IP addresses from their recent logins with timestamps and checkboxes.

1. Check the boxes next to the IPs you want to allow
2. Click **🔒 IP Lock Selected**

### Manual Entry

Type any IP address into the input field and click **Add** to add it without requiring a prior login from that address.

### Removing Entries

Click **Remove** next to any entry to remove it individually. Click **Clear All** to disable IP locking entirely for that account.

IPv4 and IPv6 addresses are both supported and treated separately.

---

## 16. Settings (Admin)

The **Settings** tab controls site-wide behaviour. All changes take effect immediately without restarting the server.

### Password Complexity

Controls what passwords are accepted: minimum length (default 12), require uppercase, require lowercase, require digit, require symbol.

### Open Tracker

When **on**, the tracker accepts BitTorrent announces for any info hash — not just torrents registered in the database. Default: off.

### Free Signup

When **on**, anyone can register a new account via the login page without an invite. Default: off.

### Torrents Per Page

Controls how many torrents are shown per page on the Dashboard, Admin Panel, user profiles, and search results. Range: 5 to 500. Default: 50.

### Auto-Promote

When **on**, Basic users are automatically promoted to Standard once they have registered at least the configured number of torrents. Default threshold: 25 torrents.

### Comments & Notifications

When **on**, the full comment and notification system is active. When **off**, the comments section is completely removed from all torrent pages and the notification bell disappears from the navbar. Default: on.

### robots.txt

The content returned at `/robots.txt`. By default, search engine crawlers are instructed to avoid `/announce`, `/scrape`, and `/manage`.

---

## 17. Economy Settings (Admin)

The **Economy** tab (Super only) contains the full economy configuration and live stats dashboard.

### Stats Dashboard

At the top of the Economy tab, a live stats panel shows:

- Total points in circulation (all user balances)
- Points currently held in bounty escrow
- Total points in debt (negative balances)
- Points generated in the last 30 days
- Points destroyed in the last 30 days (fees, house cuts)
- Breakdown of generation by transaction type (login, upload, comment, admin grant, etc.)
- Open / pending / fulfilled bounty counts

### Points Earn Settings

Controls how points are awarded:

| Setting | Default | Description |
|---------|---------|-------------|
| Daily login points | 10 | Points awarded per day on login |
| Login streak bonus | 1 | Additional points per streak day |
| Max streak bonus | 50 | Cap on streak bonus per day |
| Torrent upload points | 5 | Points per torrent registered |
| Comment points | 2 | Points per comment posted |

### Points Spend Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Invite code cost | 1,000 pts | Points spent to purchase an invite link |
| Point transfer fee | 10% | Percentage destroyed on peer-to-peer transfers |

### Bounty Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Minimum bounty escrow | 50 pts | Minimum initial escrow to create a bounty |
| Claimer payout % | 70% | Percentage of escrow paid to the claimer |
| Uploader bonus % | 10% | Additional bonus if claimer ≠ uploader |
| House cut % | 5% | Percentage destroyed |
| Requestor refund % | 25% | Partial refund of initial cost to requestor |
| Pending confirmation window | 48 hrs | Hours before an unconfirmed claim auto-expires |
| Auto-confirm vote threshold | 3 | Community votes needed to auto-confirm a claim |

### Leaderboard Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Top N per category | 10 | How many entries to show in each leaderboard category (3–100) |

### Admin Point Grants

| Setting | Default | Description |
|---------|---------|-------------|
| Max grant / removal per transaction | 1,000 pts | Maximum points an admin can grant or remove in a single action on a user's profile |

---

## 18. Invite Codes

Invite codes allow controlled onboarding without enabling open free signup.

### Admin — Invites Tab

The **Invites** tab (Admin and Super) shows all invite codes:

| Column | Description |
|--------|-------------|
| Code | Truncated token |
| Created By | Who generated it |
| Created At | When it was created |
| Status | **Pending** or **Used by username** with date |
| Actions | Copy URL and Delete (pending only) |

Click **+ Generate Invite Code** to create a new code. Use **Copy URL** to get the shareable link.

### User — Purchasing Invites with Points

The **Invite Codes** card on your profile shows your invite history. If you have enough points (default 1,000), a **Purchase Invite Link (N pts)** button appears. Clicking it shows a confirmation dialog with the exact cost before deducting.

### The Invite Link

```
https://tracker.example.net/manage/invite/abc123def456...
```

Opening the URL shows a registration form noting who invited you. The link is single-use — once consumed it cannot be reused.

---

## 19. Database Backup and Restore

The **Database** tab in the Admin Panel (Super only) provides live backup and restore without downtime.

### Creating a Backup

Click **⬇ Download Backup**. The server creates a consistent snapshot using SQLite's online backup API and downloads it as:

```
tracker-backup-YYYYMMDD-HHMMSS.db.gz
```

### Restoring from a Backup

Click **⬆ Restore from Backup**, choose a `.db.gz` file, and confirm. Before touching the live database the server validates that the file is valid gzip, the decompressed content is a real SQLite database, and passes an integrity check.

> **Important:** Take a fresh backup before restoring. The restore overwrites all current data immediately and cannot be undone.

---

## 20. Passwords

### Showing and Hiding Password Input

All password fields include an **eye button** (👁) on the right edge. Click it to reveal what you are typing. This applies to: the invite and free signup forms, the Change Password page, the Set Password (admin) page, and the Add User form.

### Changing Your Own Password

From your profile page, click **Change Password**. Enter your current password and the new password twice to confirm.

### Admin Setting Another User's Password

From a user's management page (Actions card), click **Set Password**. No knowledge of the user's current password is required.

### Forgotten Password / Lockout

There is no self-service password reset — contact an admin or superuser. If the **superuser** is locked out, the password must be reset from the command line on the server (see INSTALL.md).

### Password Security

Passwords are hashed using PBKDF2-HMAC-SHA256 with 260,000 iterations and a unique random salt per account. Plain-text passwords are never stored or logged.
