# Alternate Logging Mode (File + logrotate)

By default, `tracker.service` logs to journald/syslog.

If you want tracker output in a dedicated file (`/var/log/tracker/tracker.log`) with daily rotation, use this optional mode.

## 1. Create the log directory first

You must create the directory before enabling file logging, or the service can fail to start.

```bash
sudo mkdir -p /var/log/tracker
sudo chmod 0755 /var/log/tracker
```

## 2. Add a systemd drop-in override

Create `/etc/systemd/system/tracker.service.d/log-to-file.conf`:

```bash
sudo mkdir -p /etc/systemd/system/tracker.service.d
sudo tee /etc/systemd/system/tracker.service.d/log-to-file.conf >/dev/null <<'EOF'
[Service]
StandardOutput=append:/var/log/tracker/tracker.log
StandardError=append:/var/log/tracker/tracker.log
EOF
```

Expected file contents:

```ini
[Service]
StandardOutput=append:/var/log/tracker/tracker.log
StandardError=append:/var/log/tracker/tracker.log
```

Notes:
- With `append:...`, systemd (PID 1) opens the file, so it is commonly root-owned.
- This is expected and works fine with the logrotate config below.

## 3. Reload and restart

```bash
sudo systemctl daemon-reload
sudo systemctl restart tracker
sudo systemctl status tracker
```

Tail the dedicated log:

```bash
tail -f /var/log/tracker/tracker.log
```

## 4. Configure logrotate

Create `/etc/logrotate.d/tracker`:

```conf
/var/log/tracker/tracker.log {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    dateext
    copytruncate
    su root root
    create 0640 root adm
}
```

Why `copytruncate`:
- systemd keeps writing to the same open file descriptor.
- `copytruncate` avoids requiring a service restart during rotation.

## 5. Test rotation

```bash
sudo logrotate -d /etc/logrotate.d/tracker
sudo logrotate -f /etc/logrotate.d/tracker
ls -lah /var/log/tracker
```

## 6. Disable alternate mode (return to journald-only)

```bash
sudo rm -f /etc/systemd/system/tracker.service.d/log-to-file.conf
sudo systemctl daemon-reload
sudo systemctl restart tracker
```

Then use:

```bash
journalctl -u tracker -f
```

## 7. Clean up old journal logs

Switching to file logging does not remove historical journal entries. If `journalctl -u tracker` still shows a large backlog, vacuum old journal data.

Keep only the last 7 days:

```bash
sudo journalctl --rotate
sudo journalctl --vacuum-time=7d
```

Or cap total journal size:

```bash
sudo journalctl --rotate
sudo journalctl --vacuum-size=500M
```

Verify tracker logs after cleanup:

```bash
journalctl -u tracker --no-pager | tail -n 50
```

Optional hard reset (removes nearly all journal history):

```bash
sudo systemctl stop systemd-journald
sudo rm -f /var/log/journal/*/*.journal /run/log/journal/*/*.journal
sudo systemctl start systemd-journald
```

To enforce ongoing retention limits, configure `/etc/systemd/journald.conf` (for example `SystemMaxUse=` and `MaxRetentionSec=`), then restart `systemd-journald`.
