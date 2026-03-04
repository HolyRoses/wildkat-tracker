# Wildkat Tracker - Sandbox TLS Guide (Pre-Production)

This companion guide documents how to stand up a sandbox environment using self-signed certificates for testing before production rollout.

Use this guide for pre-production validation only.

Self-signed certificates from this guide are **not** a replacement for real public certificates from Let's Encrypt or ZeroSSL in live environments.

## Reference Hostnames Used in This Guide

- `tracker.example.net`
- `ipv4-tracker.example.net`
- `ipv6-tracker.example.net`

## 0. Sandbox Scope and Topologies

Supported test layouts:

- Server and client on the same machine (single-OS self-contained lab)
- Server and client on different machines/platforms (mixed OS testing)

Example:

- Ubuntu server + Windows client
- macOS server + Ubuntu client
- Windows server + macOS client (if Python + OpenSSL available)

## 1. Prerequisites

### Ubuntu Linux

```bash
sudo apt update
sudo apt install -y openssl ca-certificates curl
```

### macOS

```bash
brew install openssl
```

### Windows (PowerShell as Administrator)

```powershell
winget install -e --id ShiningLight.OpenSSL.Light
```

Then open a new PowerShell window and confirm:

```powershell
openssl version
```

## 1.1 Preflight Checks (Run First)

Run these checks before certificate generation or tracker startup. If a check fails, fix it first.

### macOS preflight

```bash
# toolchain
which openssl
openssl version
which python3
python3 --version

# sudo availability (non-interactive test)
sudo -n true && echo "sudo non-interactive: OK" || echo "sudo non-interactive: NEED PASSWORD/ESCALATION"

# can edit hosts file (requires sudo)
sudo test -w /etc/hosts && echo "/etc/hosts writable: OK" || echo "/etc/hosts writable: FAIL"

# can write server cert path (if using macOS path from this guide)
sudo mkdir -p /usr/local/etc/wildkat-sandbox && sudo test -w /usr/local/etc/wildkat-sandbox \
  && echo "cert dir writable: OK" || echo "cert dir writable: FAIL"

# check if privileged port 443 bind is likely blocked for non-root
python3 - <<'PY'
import socket
s=socket.socket()
try:
    s.bind(("0.0.0.0",443))
    print("bind:443 test: OK")
except Exception as e:
    print(f"bind:443 test: FAIL ({e})")
finally:
    s.close()
PY

# check if your chosen high sandbox ports can bind (example: 8443, 9443)
python3 - <<'PY'
import socket
for p in (8443, 9443):
    s=socket.socket()
    try:
        s.bind(("0.0.0.0", p))
        print(f"bind:{p} test: OK")
    except Exception as e:
        print(f"bind:{p} test: FAIL ({e})")
    finally:
        s.close()
PY
```

Notes:

- If `bind:443` fails, use non-privileged ports in sandbox (for example `--web-https-port 8443`) or run with appropriate privileges.
- If `sudo -n true` fails, interactive password entry is required. In automated agent runs, escalation is required.

### Ubuntu preflight

```bash
which openssl
openssl version
which python3
python3 --version

sudo -n true && echo "sudo non-interactive: OK" || echo "sudo non-interactive: NEED PASSWORD/ESCALATION"
sudo test -w /etc/hosts && echo "/etc/hosts writable: OK" || echo "/etc/hosts writable: FAIL"
sudo mkdir -p /etc/ssl/wildkat-sandbox && sudo test -w /etc/ssl/wildkat-sandbox \
  && echo "cert dir writable: OK" || echo "cert dir writable: FAIL"
```

### Windows preflight (PowerShell as Administrator)

```powershell
Get-Command openssl
openssl version
Get-Command python
python --version

# hosts write check
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
Test-Path $hosts

# cert store access check (LocalMachine Root)
Get-ChildItem Cert:\LocalMachine\Root | Select-Object -First 1 | Out-Null
Write-Host "Root store access: OK"
```

## 2. Discover Server IP Addresses

Run these on the server host and record the values.

### Ubuntu examples

```bash
ip -4 addr show ens3 | grep global
ip -6 addr show ens3 | grep global
```

### Generic Linux fallback

```bash
ip -4 addr | grep global
ip -6 addr | grep global
```

### macOS

```bash
# IPv4 (non-loopback)
ifconfig | awk '/inet / && $2 != "127.0.0.1" {print $2}'

# IPv6 (global/non-link-local)
ifconfig | awk '/inet6 / && $2 !~ /^fe80/ && $2 != "::1" {print $2}'

# If you know your primary interface name, this also works:
# ipconfig getifaddr en0
```

### Windows

```powershell
ipconfig
```

## 3. Create Sandbox CA, Server CSR, and Client CSR/Cert

The commands below generate:

- Root CA key + certificate
- Server key + CSR + signed server cert (with SANs)
- Client key + CSR + signed client cert
- Optional PKCS#12 client bundle for GUI import on Windows/macOS

Choose one machine as your certificate workstation (usually the sandbox server).

### 3.1 Linux/macOS copy-paste flow

```bash
mkdir -p ~/wildkat-sandbox-ca
cd ~/wildkat-sandbox-ca

# 1) Root CA
openssl genrsa -out rootCA.key 4096
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 \
  -out rootCA.crt \
  -subj "/C=US/ST=Sandbox/L=Sandbox/O=Wildkat Sandbox/OU=PKI/CN=Wildkat Sandbox Root CA"

# 2) Server key
openssl genrsa -out tracker-sandbox-server.key 4096

# 3) Server CSR config (contains SAN hostnames)
cat <<'EOF' > server-csr.cnf
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = US
ST = Sandbox
L = Sandbox
O = Wildkat Sandbox
OU = Tracker
CN = tracker.example.net

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = tracker.example.net
DNS.2 = ipv4-tracker.example.net
DNS.3 = ipv6-tracker.example.net
# Optional SAN IPs for direct-IP testing:
# IP.1 = 203.0.113.10
# IP.2 = 2001:db8::10
EOF

# 4) Create server CSR
openssl req -new -key tracker-sandbox-server.key \
  -out tracker-sandbox-server.csr -config server-csr.cnf

# 5) Server certificate extension profile
cat <<'EOF' > server-ext.cnf
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = tracker.example.net
DNS.2 = ipv4-tracker.example.net
DNS.3 = ipv6-tracker.example.net
# Optional SAN IPs for direct-IP testing:
# IP.1 = 203.0.113.10
# IP.2 = 2001:db8::10
EOF

# 6) Sign server cert with root CA
openssl x509 -req -in tracker-sandbox-server.csr \
  -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -out tracker-sandbox-server.crt -days 825 -sha256 \
  -extfile server-ext.cnf

# 7) Build fullchain for tracker server
cat tracker-sandbox-server.crt rootCA.crt > tracker-sandbox-server-fullchain.crt

# 8) Client key + CSR
openssl genrsa -out tracker-sandbox-client.key 4096
openssl req -new -key tracker-sandbox-client.key \
  -out tracker-sandbox-client.csr \
  -subj "/C=US/ST=Sandbox/L=Sandbox/O=Wildkat Sandbox/OU=Client/CN=wildkat-sandbox-client-01"

# 9) Client certificate extension profile
cat <<'EOF' > client-ext.cnf
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# 10) Sign client cert with root CA
openssl x509 -req -in tracker-sandbox-client.csr \
  -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -out tracker-sandbox-client.crt -days 825 -sha256 \
  -extfile client-ext.cnf

# 11) Optional PKCS#12 bundle for macOS/Windows client cert import
openssl pkcs12 -export \
  -inkey tracker-sandbox-client.key \
  -in tracker-sandbox-client.crt \
  -certfile rootCA.crt \
  -name "Wildkat Sandbox Client 01" \
  -passout pass:'ChangeMe123!' \
  -out tracker-sandbox-client.p12
```

> `openssl pkcs12 -export` prompts for an export password unless `-passout` is provided.  
> For copy/paste automation, keep `-passout`; for interactive mode, remove it.

### 3.2 Windows PowerShell copy-paste flow (OpenSSL)

```powershell
New-Item -ItemType Directory -Path "$env:USERPROFILE\wildkat-sandbox-ca" -Force | Out-Null
Set-Location "$env:USERPROFILE\wildkat-sandbox-ca"

openssl genrsa -out rootCA.key 4096
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 `
  -out rootCA.crt `
  -subj "/C=US/ST=Sandbox/L=Sandbox/O=Wildkat Sandbox/OU=PKI/CN=Wildkat Sandbox Root CA"

openssl genrsa -out tracker-sandbox-server.key 4096

@'
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = US
ST = Sandbox
L = Sandbox
O = Wildkat Sandbox
OU = Tracker
CN = tracker.example.net

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = tracker.example.net
DNS.2 = ipv4-tracker.example.net
DNS.3 = ipv6-tracker.example.net
# IP.1 = 203.0.113.10
# IP.2 = 2001:db8::10
'@ | Set-Content -Encoding ASCII server-csr.cnf

openssl req -new -key tracker-sandbox-server.key `
  -out tracker-sandbox-server.csr -config server-csr.cnf

@'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = tracker.example.net
DNS.2 = ipv4-tracker.example.net
DNS.3 = ipv6-tracker.example.net
# IP.1 = 203.0.113.10
# IP.2 = 2001:db8::10
'@ | Set-Content -Encoding ASCII server-ext.cnf

openssl x509 -req -in tracker-sandbox-server.csr `
  -CA rootCA.crt -CAkey rootCA.key -CAcreateserial `
  -out tracker-sandbox-server.crt -days 825 -sha256 `
  -extfile server-ext.cnf

Get-Content tracker-sandbox-server.crt, rootCA.crt | Set-Content -Encoding ASCII tracker-sandbox-server-fullchain.crt

openssl genrsa -out tracker-sandbox-client.key 4096
openssl req -new -key tracker-sandbox-client.key `
  -out tracker-sandbox-client.csr `
  -subj "/C=US/ST=Sandbox/L=Sandbox/O=Wildkat Sandbox/OU=Client/CN=wildkat-sandbox-client-01"

@'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
'@ | Set-Content -Encoding ASCII client-ext.cnf

openssl x509 -req -in tracker-sandbox-client.csr `
  -CA rootCA.crt -CAkey rootCA.key -CAcreateserial `
  -out tracker-sandbox-client.crt -days 825 -sha256 `
  -extfile client-ext.cnf

openssl pkcs12 -export `
  -inkey tracker-sandbox-client.key `
  -in tracker-sandbox-client.crt `
  -certfile rootCA.crt `
  -name "Wildkat Sandbox Client 01" `
  -passout pass:ChangeMe123! `
  -out tracker-sandbox-client.p12
```

## 4. Install Server Certificate and Key on Sandbox Server

## Ubuntu/Linux server

```bash
sudo mkdir -p /etc/ssl/wildkat-sandbox
sudo install -m 0644 ~/wildkat-sandbox-ca/tracker-sandbox-server-fullchain.crt /etc/ssl/wildkat-sandbox/fullchain.crt
sudo install -m 0640 ~/wildkat-sandbox-ca/tracker-sandbox-server.key /etc/ssl/wildkat-sandbox/server.key
sudo chown -R tracker:tracker /etc/ssl/wildkat-sandbox
sudo chmod 0750 /etc/ssl/wildkat-sandbox
```

Use these in tracker startup/service:

```text
--cert /etc/ssl/wildkat-sandbox/fullchain.crt
--key  /etc/ssl/wildkat-sandbox/server.key
```

## macOS server

```bash
sudo mkdir -p /usr/local/etc/wildkat-sandbox
sudo cp ~/wildkat-sandbox-ca/tracker-sandbox-server-fullchain.crt /usr/local/etc/wildkat-sandbox/fullchain.crt
sudo cp ~/wildkat-sandbox-ca/tracker-sandbox-server.key /usr/local/etc/wildkat-sandbox/server.key
sudo chmod 644 /usr/local/etc/wildkat-sandbox/fullchain.crt
sudo chmod 600 /usr/local/etc/wildkat-sandbox/server.key
```

## Windows server

If running Python tracker directly on Windows:

- place cert/key in a protected folder, for example:
  - `C:\wildkat-sandbox\fullchain.crt`
  - `C:\wildkat-sandbox\server.key`
- use those paths in tracker startup args.

## 5. Install Root CA Trust on Client Machines

Clients must trust `rootCA.crt` or TLS verification fails.

## Ubuntu client

```bash
sudo cp ~/wildkat-sandbox-ca/rootCA.crt /usr/local/share/ca-certificates/wildkat-sandbox-root.crt
sudo update-ca-certificates
```

## macOS client

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/wildkat-sandbox-ca/rootCA.crt
```

If your org policy blocks CLI trust changes, import via **Keychain Access**:

1. Open Keychain Access.
2. Select **System** keychain.
3. Import `rootCA.crt`.
4. Set trust to **Always Trust**.

## Windows client (PowerShell as Administrator)

```powershell
Import-Certificate -FilePath "$env:USERPROFILE\wildkat-sandbox-ca\rootCA.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

## 6. Install Client Certificate (Optional mTLS Testing)

Wildkat tracker does not require client cert auth by default. This is optional for front-end proxy or mTLS lab tests.

### Import PKCS#12 on macOS

```bash
security import ~/wildkat-sandbox-ca/tracker-sandbox-client.p12 -k ~/Library/Keychains/login.keychain-db
```

### Import PKCS#12 on Windows

```powershell
Import-PfxCertificate -FilePath "$env:USERPROFILE\wildkat-sandbox-ca\tracker-sandbox-client.p12" -CertStoreLocation Cert:\CurrentUser\My
```

### Ubuntu client cert usage (CLI)

Use cert/key files directly with curl:

```bash
curl --cert ~/wildkat-sandbox-ca/tracker-sandbox-client.crt \
     --key ~/wildkat-sandbox-ca/tracker-sandbox-client.key \
     --cacert ~/wildkat-sandbox-ca/rootCA.crt \
     https://tracker.example.net/
```

## 7. Update Hosts Files (Server and Clients)

You can test with DNS or local hosts overrides.

For lab-only local name mapping, add entries on both server and client machines.

Replace the sample IPs with your real sandbox server addresses from Step 2.

Example mappings:

- IPv4 server: `203.0.113.10`
- IPv6 server: `2001:db8::10`

## Ubuntu/macOS hosts update

```bash
cat <<'EOF' | sudo tee -a /etc/hosts
203.0.113.10 tracker.example.net ipv4-tracker.example.net
2001:db8::10 tracker.example.net ipv6-tracker.example.net
EOF
```

If client and server are same machine:

```bash
cat <<'EOF' | sudo tee -a /etc/hosts
127.0.0.1 tracker.example.net ipv4-tracker.example.net
::1       tracker.example.net ipv6-tracker.example.net
EOF
```

## Windows hosts update (PowerShell as Administrator)

```powershell
@'
203.0.113.10 tracker.example.net ipv4-tracker.example.net
2001:db8::10 tracker.example.net ipv6-tracker.example.net
'@ | Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts"
```

## 8. Configure Tracker for Sandbox Hostnames

Example tracker args (adapt paths/ports as needed).

Use platform-appropriate paths:

- Ubuntu/Linux example:
  - server script: `/opt/tracker/tracker_server.py`
  - cert/key: `/etc/ssl/wildkat-sandbox/fullchain.crt`, `/etc/ssl/wildkat-sandbox/server.key`
  - db: `/opt/tracker/tracker.db`
- macOS example:
  - server script: `/usr/local/opt/tracker/tracker_server.py` (or your repo path)
  - cert/key: `/usr/local/etc/wildkat-sandbox/fullchain.crt`, `/usr/local/etc/wildkat-sandbox/server.key`
  - db: `/usr/local/var/wildkat/tracker.db` (or your preferred path)
- Windows example:
  - server script: `C:\tracker\tracker_server.py`
  - cert/key: `C:\wildkat-sandbox\fullchain.crt`, `C:\wildkat-sandbox\server.key`
  - db: `C:\tracker\tracker.db`

### Ubuntu/Linux sample

```bash
python3 /opt/tracker/tracker_server.py \
  --http-port 8080 \
  --https-port 8443 \
  --udp-port 6969 \
  --web-https-port 443 \
  --web-redirect-http \
  --cert /etc/ssl/wildkat-sandbox/fullchain.crt \
  --key /etc/ssl/wildkat-sandbox/server.key \
  --redirect-http \
  --domain tracker.example.net:8443 \
  --registration \
  --super-user super \
  --db /opt/tracker/tracker.db
```

### macOS sample

```bash
python3 /usr/local/opt/tracker/tracker_server.py \
  --http-port 8080 \
  --https-port 8443 \
  --udp-port 6969 \
  --web-https-port 443 \
  --web-redirect-http \
  --cert /usr/local/etc/wildkat-sandbox/fullchain.crt \
  --key /usr/local/etc/wildkat-sandbox/server.key \
  --redirect-http \
  --domain tracker.example.net:8443 \
  --registration \
  --super-user super \
  --db /usr/local/var/wildkat/tracker.db
```

### Windows sample (PowerShell)

```powershell
python C:\tracker\tracker_server.py `
  --http-port 8080 `
  --https-port 8443 `
  --udp-port 6969 `
  --web-https-port 443 `
  --web-redirect-http `
  --cert C:\wildkat-sandbox\fullchain.crt `
  --key C:\wildkat-sandbox\server.key `
  --redirect-http `
  --domain tracker.example.net:8443 `
  --registration `
  --super-user super `
  --db C:\tracker\tracker.db
```

## 9. Validation Commands

## TLS certificate check

```bash
openssl s_client -connect tracker.example.net:8443 -servername tracker.example.net -showcerts
```

## Curl trust check

```bash
curl --cacert ~/wildkat-sandbox-ca/rootCA.crt https://tracker.example.net:8443/
```

## Tracker query check

```bash
# HTTPS announce against primary SAN
./tracker_query.py -t https://tracker.example.net:8443/announce

# HTTPS announce against dedicated IPv4 SAN hostname
./tracker_query.py -t https://ipv4-tracker.example.net:8443/announce

# HTTPS announce against dedicated IPv6 SAN hostname
./tracker_query.py -t https://ipv6-tracker.example.net:8443/announce

# HTTPS scrape (replace with a real 40-char hex info hash)
./tracker_query.py -t https://tracker.example.net:8443/announce -s -H <info_hash_hex>

# HTTPS scrape via dedicated IPv4 SAN hostname
./tracker_query.py -t https://ipv4-tracker.example.net:8443/announce -s -H <info_hash_hex>

# HTTPS scrape via dedicated IPv6 SAN hostname
./tracker_query.py -t https://ipv6-tracker.example.net:8443/announce -s -H <info_hash_hex>

# UDP announce
./tracker_query.py -t udp://tracker.example.net:6969/announce

# UDP scrape
./tracker_query.py -t udp://tracker.example.net:6969/announce -s -H <info_hash_hex>
```

### No-sudo CLI validation path (optional)

If you cannot update `/etc/hosts` or system trust yet, you can still validate TLS + hostname using `--resolve` and `--cacert`.

```bash
curl --cacert ~/wildkat-sandbox-ca/rootCA.crt \
  --resolve tracker.example.net:8443:127.0.0.1 \
  https://tracker.example.net:8443/
```

This validates:

- certificate chain against your sandbox root CA
- hostname/SNI (`tracker.example.net`)
- HTTPS endpoint reachability

## 10. Teardown and Cleanup (Certs + Hosts)

Use these steps when you want to fully remove sandbox trust, sandbox cert files, and hostname overrides.

## 10.1 Remove hosts-file sandbox entries

### Ubuntu/macOS

```bash
sudo cp /etc/hosts /etc/hosts.bak.$(date +%Y%m%d%H%M%S)
grep -v 'example.net' /etc/hosts | sudo tee /etc/hosts >/dev/null
```

### Windows (PowerShell as Administrator)

```powershell
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
Copy-Item $hostsPath "$hostsPath.bak.$(Get-Date -Format yyyyMMddHHmmss)"
(Get-Content $hostsPath) | Where-Object { $_ -notmatch 'wildkat-sandbox\.net' } | Set-Content -Encoding ascii $hostsPath
```

## 10.2 Remove root CA trust from client machines

### Ubuntu client

```bash
sudo rm -f /usr/local/share/ca-certificates/wildkat-sandbox-root.crt
sudo update-ca-certificates --fresh
```

### macOS client

```bash
sudo security delete-certificate -c "Wildkat Sandbox Root CA" /Library/Keychains/System.keychain
```

### Windows client (PowerShell as Administrator)

```powershell
Get-ChildItem Cert:\LocalMachine\Root |
  Where-Object { $_.Subject -match 'CN=Wildkat Sandbox Root CA' } |
  Remove-Item
```

## 10.3 Remove optional client certificate installs

### macOS client

```bash
security find-certificate -a -c "Wildkat Sandbox Client 01" ~/Library/Keychains/login.keychain-db
security delete-certificate -c "Wildkat Sandbox Client 01" ~/Library/Keychains/login.keychain-db
```

### Windows client

```powershell
Get-ChildItem Cert:\CurrentUser\My |
  Where-Object { $_.Subject -match 'CN=wildkat-sandbox-client-01' } |
  Remove-Item
```

## 10.4 Remove sandbox cert/key files from server

### Ubuntu/Linux server

```bash
sudo rm -rf /etc/ssl/wildkat-sandbox
```

### macOS server

```bash
sudo rm -rf /usr/local/etc/wildkat-sandbox
```

### Windows server (PowerShell as Administrator)

```powershell
Remove-Item -Recurse -Force C:\wildkat-sandbox
```

## 10.5 Remove local certificate workspace files (optional)

Linux/macOS:

```bash
rm -rf ~/wildkat-sandbox-ca
```

Windows:

```powershell
Remove-Item -Recurse -Force "$env:USERPROFILE\wildkat-sandbox-ca"
```

## 10.6 DNS/OS cache refresh after hosts or trust changes (optional)

Ubuntu (if systemd-resolved):

```bash
sudo resolvectl flush-caches
```

macOS:

```bash
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

Windows:

```powershell
ipconfig /flushdns
```

## 11. Promotion to Production

Before going live:

- re-run checks against production hostnames
- replace self-signed certs with public CA certs (Let's Encrypt or ZeroSSL)
- remove sandbox-only hosts file overrides

Sandbox is for testing and pre-production verification only.

## Troubleshooting

### `PermissionError: [Errno 1] Operation not permitted` on server startup

If tracker startup fails while binding ports, your OS policy/environment is blocking socket bind operations for this process.

Actions:

1. Re-run preflight bind checks for the exact ports you plan to use.
2. Use non-privileged ports (for example 8443/9443) when possible.
3. Ensure no other process is already bound to those ports.
4. If policy restrictions still block bind, run with appropriate privileges or adjust local security policy.

### Browser still warns after root CA install

1. Confirm hostname in URL matches certificate SAN (`tracker.example.net`, etc.).
2. Confirm hosts/DNS points to the intended sandbox server.
3. Recheck root CA install in system trust store.
4. Restart browser after trust-store changes.
