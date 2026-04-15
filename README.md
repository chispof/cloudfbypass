# CF Bypass Proxy

A MITM proxy that spoofs the Chrome JA3/TLS fingerprint to bypass Cloudflare bot detection. Designed for use alongside Burp Suite in authorized security testing and web analysis workflows.

## Architecture

```
Browser → Burp (8080) → CF Bypass Proxy (8082) → Cloudflare (Chrome JA3)
```

The proxy terminates TLS from Burp using a dynamically generated certificate signed by a local CA, then forwards the request to the target server using a Chrome 120 TLS fingerprint via [`tls-client`](https://github.com/bogdanfinn/tls-client).

## Features

- Spoofs Chrome 120 JA3/TLS fingerprint (`chrome_120` profile)
- Dynamically generates per-domain TLS certificates signed by a local CA
- Persistent sessions per domain (preserves `cf_clearance` cookies across requests)
- Overrides browser-identifying headers (`User-Agent`, `Sec-CH-UA-*`, etc.)
- Supports `CONNECT` tunneling (HTTPS) and plain HTTP
- Detailed 403 diagnostic logging

## Requirements

```bash
pip install tls-client cryptography
```

## Setup

### 1. Run the proxy

```bash
python3 cf_bypass_proxy.py
```

On first run it generates `cf_bypass_ca.pem` and `cf_bypass_ca.key`.

### 2. Import the CA into Burp Suite

`Settings → Network → TLS → CA Certificates → Import` → select `cf_bypass_ca.pem`

### 3. Configure Burp upstream proxy

`Settings → Network → Connections → Upstream Proxy Rules → Add`

| Field    | Value       |
|----------|-------------|
| Host     | `127.0.0.1` |
| Port     | `8082`      |
| Protocol | `HTTP`      |

### 4. Browse normally

All traffic flows: `Browser → Burp (8080) → CF Bypass Proxy (8082) → Target`

## Configuration

Edit the constants at the top of `cf_bypass_proxy.py`:

| Variable        | Default             | Description                              |
|-----------------|---------------------|------------------------------------------|
| `PROXY_HOST`    | `127.0.0.1`         | Listening address                        |
| `PROXY_PORT`    | `8082`              | Listening port                           |
| `TARGET_DOMAIN` | `pichinchamiles.com`| Filter to a specific domain (`""` = all) |
| `TLS_PROFILE`   | `chrome_120`        | TLS fingerprint profile to impersonate   |

## Files

| File                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `cf_bypass_proxy.py`  | Main proxy script                                |
| `cf_bypass_ca.pem`    | Generated CA certificate (import into Burp)      |
| `cf_bypass_ca.key`    | Generated CA private key (keep private)          |

## Disclaimer

This tool is intended for **authorized security testing and research only**. Only use it against systems you own or have explicit permission to test.
