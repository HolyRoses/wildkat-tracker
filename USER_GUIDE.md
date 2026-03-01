# Wildkat Tracker — User Guide

This guide covers the registration mode web interface at `/manage`. It is intended for both regular users and administrators.
It focuses on UI operations and behavior. Server deployment and OS-level setup are covered in `INSTALL.md`.

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
9. [Direct Messages](#9-direct-messages)
10. [Searching Torrents](#10-searching-torrents)
11. [Points Economy](#11-points-economy)
12. [Bounty Board](#12-bounty-board)
13. [Leaderboard](#13-leaderboard)
14. [Admin Panel](#14-admin-panel)
15. [User Management (Admin)](#15-user-management-admin)
16. [IP Allowlist and IP Lock](#16-ip-allowlist-and-ip-lock)
17. [Settings (Admin)](#17-settings-admin)
18. [Economy Settings (Admin)](#18-economy-settings-admin)
19. [Invite Codes](#19-invite-codes)
20. [Database Backup and Restore](#20-database-backup-and-restore)
21. [Passwords](#21-passwords)
22. [Top-ups and Payments](#22-top-ups-and-payments)
23. [Followers System](#23-followers-system)

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

Visit `https://tracker.example.net/manage`. Enter your username and password and click **Login**. Sessions last 48 hours. If you close the browser the session cookie remains until it expires.

Sessions are HTTPS-only — the cookie cannot be sent over plain HTTP.

If passkey login is enabled by the operator, the login form also shows **Sign in with Passkey**. Enter your username first, then start passkey login. If the first authenticator prompt is not the one you want, use the switch guidance in [Passkey Device Switching at Login](#passkey-device-switching-at-login).

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

The **navigation bar** runs across the top of every page with three zones: the 🐈 WILDKAT logo on the left, center navigation buttons (🖥 Dashboard, 🔍 Search, 🎯 Bounties, 🏆 Leaderboard, 📬 Messages), and your username/badge, notification bell, and logout on the right. The Bounties, Leaderboard, and Messages buttons are hidden for Basic users.

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

### Upload Limits and Partial Success

The upload form enforces server-side limits configured by admins:

- Max request size (MB)
- Max files per upload
- Max per-file size (MB)

If a batch includes files over per-file limits (or files beyond the max file count), valid files are still processed and registered. The result summary reports registered, skipped duplicates, skipped over-limit, and invalid files.

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
- **Seeders / Peers / Downloads** — latest stored peer snapshot values
- **Last Peer Update** — time of the last successful peer snapshot refresh
- **Peer Source** — announce URL used for the last successful snapshot

Below the info card is the **file list** — every file in the torrent with its exact size.

The **Copy Magnet Link** button builds a magnet URI from the info hash, torrent name, total size, and the active tracker URLs configured in the Admin Panel.

### Refresh Seeds/Peers

If peer-query settings are enabled by Super, the torrent Actions card includes **Refresh Seeds/Peers**.

- The refresh is manual and per-torrent.
- Cooldown: one successful refresh every 3 hours for the same torrent.
- During cooldown, the button remains visible but disabled and shows remaining time.
- On success, Seeders/Peers/Downloads, Last Peer Update, and Peer Source are updated.
- On failure or no-data responses, existing stored counts are not overwritten.
- Optional tracker setting can auto-queue peer refreshes after successful uploads (background, non-blocking).

If there are confidently linked active members in the swarm, a full-width **Members Currently Sharing This Torrent** card appears with member links and last activity times. If no linked members are active, the card is not shown.

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

When someone replies to your comment, @mentions you, or bounty events occur, a 🔔 badge appears in the navigation bar.

**Bell dropdown** — click the bell to see your 5 most recent unread notifications. Each item shows who acted, what they did, and which torrent or bounty it relates to. Click any item to mark it read and navigate to the relevant page.

**Notifications page** (`/manage/notifications`) — shows all notifications, read and unread. Use **✓ Mark all read** to clear everything at once.

### Bounty Notifications

In addition to comment notifications, the bell delivers bounty-related events:

| Icon | Event |
|------|-------|
| 📣 | Someone posted a new bounty |
| @ | Someone @mentioned you in bounty discussion |
| 🎯 | Someone claimed your bounty |
| ✗ | Your claim was rejected |
| ✅ | Your bounty claim was accepted |
| ➕ | Someone added points to your bounty |
| ⏰ | Your bounty expired without being fulfilled |
| 💰 | Someone fulfilled a bounty using your upload |
| 👥 | Someone started following you |
| 📦 | Someone you follow uploaded a torrent |
| ✅ | Someone you follow fulfilled a bounty |

---

## 7. Your Profile

Click your **username** in the top navigation bar to go to your profile page.

Your profile shows:

- Your role badge and status badges (locked, disabled) if applicable
- **Account Details** — join date, created-by (shows "Invited by username" if you joined via invite), login count, last login, last password change, failed attempts, current **Points** balance (color-coded red if negative), and current **Login Streak** if you are on a streak
- **Actions card** — Change Password button
- **Followers link** — quick entry to followers/following page
- IP Allowlist — if your account has IP-locking enabled
- **Invite Codes** — your pending and consumed invite codes, and the Purchase Invite Link button if you have enough points
- All your registered torrents with pagination
- **Danger Zone** — delete all your torrents at once (permanent)

### Layout

Your profile page uses a two-column layout matching other profile views. The left column shows Account Details. The right column stacks: **Actions**, **Invite Codes**, and **Send Points**. Below the two columns are your Bounty history, Points History, Danger Zone, and registered torrents.

### Actions Card

The Actions card contains:

- **Change Password** button
- **Messaging & Privacy toggles**:
  - Allow others to send me DMs
  - Show my online status to others
  - Bounty alerts (new bounty notifications)
  - Allow linking my torrent swarm activity
  - Use Gravatar avatar
  - Gravatar email or MD5 hash input (stores only the hash)
  - Passkey settings:
    - Enable passkey sign-in
    - Prefer passkey on this account
    - Require passkey (password-only login blocked)
    - Add passkey
    - Rename/remove passkeys

### Passkey Device Switching at Login

In your profile's passkey table, each row has a **Save** action. Clicking it saves the passkey name and sets that credential as your account's primary passkey.

The primary passkey is used first on the next passkey login attempt. In most cases this lets you go directly to the authenticator you want, without canceling prompts to switch devices at the login screen.

Supported passkey authenticator types include:

- Hardware security keys (for example, Google Titan Key and YubiKey)
- Apple platform authenticators (Touch ID / Face ID)
- Browser/platform-managed passkeys (for example, Chrome passkeys)

If a member does not have a physical security key and is not using Apple Touch ID/Face ID, they can still authenticate with a browser-managed passkey when the browser offers that option.

Browser prompt behavior can vary by browser and OS. The account's selected primary passkey is attempted first when the browser allows it.

If your browser shows an Apple Touch ID/Face ID prompt but you want to use a different physical security key (for example, Titan Key), use this flow:

1. Cancel the Apple passkey prompt.
2. If needed, cancel once more (some browsers require two cancels before they re-check other authenticators).
3. Wait for the Apple prompt to appear again.
4. Press the button on your physical security key.

When authentication succeeds with that device, it becomes your preferred (primary) passkey for future sign-ins.

If you are prompted for a physical security key (for example, Titan Key) and want to switch back to Apple Touch ID/Face ID:

1. Cancel the security-key prompt.
2. If needed, cancel a second time so the browser refreshes available authenticators.
3. Wait for the Apple prompt to appear.
4. Authenticate with Touch ID or Face ID.

### Self-Delete Account

Your profile Actions card includes a **Danger Zone** self-delete flow.

- Start by typing `DELETE MY ACCOUNT` and submitting the delete request.
- The system immediately signs you out and starts a short deletion challenge window (default 5 minutes).
- Sign in again within the window. If a valid challenge exists, you are routed to a dedicated confirmation page.
- Final confirmation requires:
  - your current password
  - re-typing `DELETE MY ACCOUNT`
  - a final irreversible confirmation prompt
- If successful, the account is removed, sessions are revoked, and a goodbye page is shown.
- If the challenge expires, or too many failed confirmation attempts occur, you must restart from your profile.
- The Super account cannot self-delete.

### Points and Invite Generation

Your current points balance is shown in the **Account Details** card. Points are earned automatically for daily logins (with streak bonuses), torrent uploads, and comments. See [Section 11](#11-points-economy) for full details.

The **Invite Codes** card shows your invite history. If you have enough points (default 1,000), a **Purchase Invite Link (N pts)** button appears. Clicking it shows a confirmation dialog stating exactly how many points will be spent, then creates a new invite code. If you do not have enough points the button is shown but disabled with the shortfall displayed.

The **Send Points** card lets you transfer points to another user directly from your profile. See [Section 11](#11-points-economy) for transfer details.

---

## 8. User Profiles

Standard, Admin, and Super users can view public profiles of other users by clicking their username in any listing or navigating to `/manage/user/{username}`.

A public profile shows:

- The user's role badge
- Status (Online / Recently active / Offline, unless hidden by the user)
- Member Since date
- **Points** balance (color-coded)
- **Login Streak** (if active)
- Total torrent count
- Followers and following counts
- Their full paginated torrent list

Status behaviour:
- **Online** — user has an active web session
- **Recently active** — no active session, but seen within the recent activity window
- **Offline** — no active session and outside the recent activity window

When the profile owner has activity-linking enabled and has active, confidently linked swarm participation, a full-width card appears:

- **Currently sharing N torrents** — list of clickable torrent links plus last activity time

If the profile owner opts out of torrent activity linking, this card is hidden for everyone (including the owner).

**What is not shown** on a public profile: login count, last login, failed login attempts, created-by, password history, IP addresses, or any administrative controls.

Basic users are redirected to their dashboard if they attempt to view a profile.

If you are an Admin or Super, a small **⚙ Admin View** link appears on the public profile page that takes you directly to the full administrative view of that user.

A **📬 Send DM** button appears in the profile sub-header for eligible Standard+ viewers when DMs are enabled site-wide and the profile owner has not disabled DMs. Clicking it opens the compose form pre-addressed to that user.

A **Follow** button appears on profile pages for other users. Follow and unfollow actions are instant.

---

## 9. Direct Messages

The Direct Messages system lets Standard+ users send private messages to each other. Navigate to it via the **📬 Messages** button in the navigation bar (Standard+ only).

### The Messages Page

The Messages page has four tabs:

| Tab | Description |
|-----|-------------|
| **Inbox** | Messages you have received, newest first. Unread messages are highlighted. |
| **Sent** | Messages you have sent. |
| **Compose** | Send a new message. |
| **Blocked** | Users you have blocked. |

### Composing a Message

Click the **Compose** tab. Fill in:

- **To** — one username or multiple separated by semicolons (e.g. `alice; bob; carol`)
- **Subject** — optional
- **Message** — your message body

Click **Send Message**. Each recipient receives a separate DM. All recipients are validated before any messages are sent — if any are invalid the send is aborted and the errors are listed. If the daily send limit allows fewer messages than recipients, the first N recipients receive the message and the rest are reported as skipped.

In compose/reply textareas, **Enter sends** and **Shift+Enter inserts a newline**.

**Point cost:** each DM sent deducts a configurable number of points (default 5 pts). Multi-recipient sends deduct the total in one transaction. Admins and Super are exempt from point costs and daily limits.

### Conversation Threads

Clicking any message in the Inbox or Sent tab opens the conversation thread with that user. The thread shows the full message history between you two as chat bubbles — your messages on the right, theirs on the left. Reply using the form at the bottom.

The conversation header shows:
- **❮ Messages** — back to inbox
- **👤 Name's Profile** — link to the other user's profile
- **🚫 Block / Unblock** — toggle blocking from within the thread

### Blocking Users

You can block a user from inside a conversation thread or from the **Blocked** tab on the Messages page.

- Blocked users cannot send you DMs
- You can still send messages to a blocked user
- The blocked user receives a vague "not accepting messages" error — they cannot tell whether they are blocked or you have simply disabled DMs
- Admins and Super cannot be blocked
- Unblock at any time from the Blocked tab or from the conversation thread

### Opting Out of DMs

To stop receiving DMs from anyone, go to your profile → Actions card → uncheck **Allow others to send me DMs** and click **Save**. You can re-enable this at any time. Senders receive the same vague error regardless of whether you have blocked them or opted out.

### Admin — DM Broadcast (Super only)

The Superuser can send a broadcast message to all users at once from the Compose tab. A **Broadcast to all users** checkbox appears in the compose form for Super only.

---

## 10. Searching Torrents

Click the **🔍 Search** button in the navigation bar or navigate to `/manage/search`.

The search engine splits your query into individual tokens and matches each one independently. Dots, dashes, and underscores in torrent names are treated as spaces, so you can search naturally:

- `ubuntu 24` matches `ubuntu-24.04.2-live-server-amd64.iso`
- `ubuntu 24 server` also matches — all three tokens must be present
- `ubuntu 24 desktop` does not match — `desktop` is not in the name
- Searching by info hash fragment also works

All tokens must match (AND logic). The search is case-insensitive.

Basic users see only their own torrents in search results. Standard and above see all torrents on the tracker.

---

## 11. Points Economy

The points system is the site's internal currency. Points are earned, spent, transferred, and destroyed according to rules the admin configures. There is no way to acquire points outside the system.

### Earning Points

| Activity | Points |
|----------|--------|
| Daily login | Configurable base amount (default: 1 pt) |
| Login streak bonus | Milestone bonuses (default: +1 at 7 days, +4 at 30 days) |
| Registering a torrent | Configurable per upload (default: 25 pts) |
| Posting a comment | Configurable per comment (default: 1 pt, daily cap applies) |

Streaks reset if you miss a day. The current streak is shown on your profile and the leaderboard.

### Spending Points

| Activity | Cost |
|----------|------|
| Purchasing an invite code | 1,000 pts (default, configurable by admin) |
| Creating a bounty | Variable — you set the initial escrow amount |
| Contributing to a bounty | Variable — you choose how much to add |
| Sending a direct message | Configurable per-recipient cost (default 5 pts). Exempt for Admin/Super |
| Sending points to another user | Amount + transfer fee % |
| Purchasing points (Top-ups) | USD payment amount selected in Top-ups |

### Point Transfers

Standard+ users can send points to other users directly from their profile or from the recipient's public profile. A configurable fee percentage is taken and **destroyed** (not redistributed) — this is deflationary by design. The transfer is logged in the event log.

### Negative Balances

Points balances can go negative (shown in red). This happens when a user has spent more than they have earned. Negative-balance users can still use the site normally but cannot make purchases until they return to a positive balance.

---

## 12. Bounty Board

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

## 13. Leaderboard

Navigate to **🏆 Leaderboard** in the nav bar (Standard+ only). The leaderboard shows the top N users (configurable by admin, default 10) in six categories.

| Category | Metric |
|----------|--------|
| 💰 Top Holders | Current points balance — who has the most points right now |
| 📈 All-Time Earners | Total points ever earned — spending does not hurt your rank |
| 📦 Top Uploaders | Most torrents registered on the tracker |
| 🎯 Bounty Hunters | Most bounties successfully fulfilled |
| 🔥 Login Streaks | Longest current consecutive daily login streak |
| 💬 Most Chatty | Most comments posted across all torrents |
| 👥 Most Followed | Most followers across Standard/Admin users |

Top 3 in each category receive 🥇🥈🥉 medals. All usernames link to public profiles. Rankings update in real time.

---

## 14. Admin Panel

Accessible to Admin and Super only via the **⚙ Admin Panel** link (visible on the dashboard for admins).

The Admin Panel has eleven tabs:

### Torrents Tab

All registered torrents across all users, paginated. Includes the owner column. Admins and Super can delete any torrent from this view.

### Users Tab

All registered accounts with role badges, creation date, login count, and last login. Click a username to open their full management page. Each row includes a **Set Password** button.

### Add User Tab

Create a new account by specifying username, password, and role (Basic, Standard, or Admin).

### Trackers Tab

Manage the tracker URLs embedded in generated magnet links. Each tracker can be individually enabled or disabled.

The Trackers tab also includes a **Torrent Seeds/Peers Query** card used by manual torrent-page peer refresh and optional upload-triggered background refresh.

It contains:

- **Enable seeds/peers query updates**
- **Scrape Input (announce URL)** — example: `http://tracker.opentrackr.org:1337/announce`
- **Tracker Query Tool Path** — default example: `/opt/tracker/tracker_query.py`
- **Tracker Query Arguments** — default pattern: `-o json -s -r -H {hash} -t {tracker}`
- **Retry Attempts** — default `3`
- **Retry Wait (sec)** — default `2`
- **Auto-run peer updates on successful uploads** — optional toggle
- **Auto update cap per upload** — max queued torrents per upload batch (default `5`)

Validation rules:

- Enabling fails unless all query fields are filled.
- Arguments must include both placeholders: `{hash}` and `{tracker}`.
- Arguments must request JSON output.
- Saving fails if the configured tool path does not exist.
- Auto-run upload refresh uses a background queue so upload responses return immediately.

### Settings Tab

See [Section 17](#17-settings-admin).

### Database Tab

See [Section 20](#20-database-backup-and-restore). Visible to Super only.

### Economy Tab

See [Section 18](#18-economy-settings-admin). Visible to Super only.

### Top-ups Tab

See [Section 22](#22-top-ups-and-payments). Visible to Super only.

### Invites Tab

See [Section 19](#19-invite-codes). Visible to Admin and Super.

### Danger Tab

Bulk-delete operations and System Wipe. Visible to Super only. See [Section 15](#15-user-management-admin).

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

## 15. User Management (Admin)

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
- **Passkey Optional / Enforce Passkey** — admins and super can enforce per-user passkey requirement from Admin View
- **Reset Passkeys** — admins and super can clear a user's passkeys for account recovery

### Super-Only Danger Operations

The **Danger** tab in the Admin Panel contains four operations accessible only to the Superuser:

- **Delete All Users** — permanently deletes every account except the super account. All sessions are invalidated
- **Delete All Torrents** — permanently removes every registered torrent
- **Delete All Comments & Notifications** — removes every comment and notification system-wide
- **☢ System Wipe** — wipes all users (except super), all torrents, all comments, all notifications, all invite codes, all sessions, and the entire event log. Returns the tracker to near-factory state

The System Wipe requires a two-step typed confirmation: first type `SYSTEMWIPE` exactly, then a final confirmation screen.

---

## 16. IP Allowlist and IP Lock

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

## 17. Settings (Admin)

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

### Direct Messages

| Setting | Default | Description |
|---------|---------|-------------|
| Enable DMs | on | Master switch — when off, the Messages button is hidden and no DMs can be sent |
| Point cost per DM | 5 pts | Points deducted per recipient per send. Admins and Super are exempt |
| Daily send limit | 10 | Maximum DMs a user can send per calendar day. Admins and Super are exempt |

### Upload Limits

| Setting | Default | Description |
|---------|---------|-------------|
| Upload max request size | 100 MB | Maximum total HTTP request body accepted by `/manage/upload` |
| Upload max files | 1000 | Maximum files accepted in one upload batch |
| Upload max per-file size | 10 MB | Maximum size for an individual `.torrent` file |

### Gravatar Integration

| Setting | Default | Description |
|---------|---------|-------------|
| Enable Gravatar avatars | off | Global switch for external Gravatar avatar rendering in the web UI. Users may supply email or MD5 hash; stored value is hash-only |

### Passkey Settings and Super Recovery

Passkey login can be enabled and enforced from Settings.

Available settings:

- **Enable WebAuthn login** — enables passkey login support
- **Enforce passkey for Admin + Super accounts** — requires passkeys for admin/super roles
- **Enforce passkey site-wide** — requires passkeys for all users

Enforcement behavior:

- If enforcement applies and a user has no passkey yet, they are routed to a required passkey enrollment page after login/signup.
- If enforcement applies and a user already has passkeys, password-only login is blocked for that account.
- On profile settings, enforcement displays a policy notice:
  - `Server policy is enforcing passkey requirements.`
  - or `Admin policy is enforcing passkey requirement for this account.`

If enforcement is active and the superuser loses passkey access, use CLI recovery.

Run recovery commands as the service account (example super account name: `super`):

```bash
sudo -u tracker /opt/tracker/tracker_server.py \
  --registration \
  --db /opt/tracker/tracker.db \
  --super-user super \
  --manage-port 443 \
  --super-user-reset-passkeys
```

What this does:

- Removes all passkeys from the super account
- Clears active sessions for that account
- Allows fresh password login and re-enrollment of passkeys

To reset only the super password:

```bash
sudo -u tracker /opt/tracker/tracker_server.py \
  --registration \
  --db /opt/tracker/tracker.db \
  --super-user super \
  --manage-port 443 \
  --super-user-password 'NEW_STRONG_PASSWORD'
```

If your deployment uses a separate management TLS configuration, include the same TLS flags used by your service startup command.

---

## 18. Economy Settings (Admin)

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
| Daily login points | 1 | Points awarded per day on login |
| 7-day streak bonus | 1 | Extra points when user hits a 7-day streak |
| 30-day streak bonus | 4 | Extra points when user hits a 30-day streak |
| Torrent upload points | 25 | Points per torrent registered |
| Comment points | 1 | Points per comment posted |
| Comment points daily cap | 10 | Maximum comment points earned per day |

### Points Spend Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Invite code cost | 1,000 pts | Points spent to purchase an invite link |
| Point transfer fee | 25% | Percentage destroyed on peer-to-peer transfers |

### Bounty Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Minimum bounty escrow | 50 pts | Minimum initial escrow to create a bounty |
| Claimer payout % | 70% | Percentage of escrow paid to the claimer |
| Uploader bonus % | 15% | Additional bonus if claimer ≠ uploader |
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

## 19. Invite Codes

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

## 20. Database Backup and Restore

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

## 21. Passwords

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

---

## 22. Top-ups and Payments

Top-ups let eligible users purchase points using enabled payment providers.

### User Flow

Users open `/manage/topups` to:

- Select a fixed USD amount
- Select a provider (if more than one is enabled)
- Create an order and continue to provider checkout
- Return to Wildkat and view updated order status

Order history is shown on the Top-ups page and includes provider, amount, quoted points, status, and timestamps.

### Provider Behavior

- If only one payment provider is enabled, the UI shows that provider as a fixed label.
- If multiple providers are enabled, a selector is shown.
- Capture/confirmation can complete via provider return flow or provider webhook flow.
- Duplicate events are safely ignored; each order can only be credited once.

### Status Lifecycle

| Status | Meaning |
|--------|---------|
| created | Order record created |
| pending | Awaiting provider completion or callback |
| confirmed | Provider confirmation received |
| credited | Points posted to balance |
| refunded | Payment reversed; points deducted |
| exception | Needs admin review |

### Super/Admin Controls

In **Admin Panel → Top-ups** (Super only), operators configure:

- Global top-up enable/disable
- Rollout mode (`admin_only` or `all_users`)
- Coinbase and PayPal enable/disable
- Sandbox/live credentials for both providers
- Webhook secrets/IDs and PayPal webhook enforcement mode
- Pricing model: base rate, fixed amounts, and multiplier bands
- Timeout and pending-SLA behavior

### Reconciliation and Safety

- Stale orders are reconciled automatically into exception state when they exceed SLA without completion.
- Refund/reversal webhooks reverse previously credited points.
- Top-up actions are recorded in event logs and top-up order history for auditability.

---

## 23. Followers System

The followers system lets users subscribe to activity from other members.

### Follow and Unfollow

- On another user's profile, click **Follow** to start following.
- If already following, the button shows **✅ Following** and changes to **❌ Unfollow** on hover.
- Clicking unfollow removes the relationship immediately.
- Self-follow is blocked.
- Duplicate follow attempts are ignored safely.

### Followers Page

Open `/manage/following` (also linked from your profile/actions area).

The page has two lists:

- **Followers** — users following you
- **Following** — users you follow

Each row links to the user's profile and includes quick follow/unfollow actions.

### Notifications from Follows

You receive notifications when:

- someone starts following you
- someone you follow uploads a new torrent
- someone you follow fulfills a bounty

Notification clicks redirect directly to the related profile, torrent, or bounty page.

### Role Behavior

- Basic users cannot browse arbitrary public profiles.
- Basic users can still use the followers page and follow-back actions when another member has followed them.
- Standard/Admin/Super users can follow from profile pages directly.
