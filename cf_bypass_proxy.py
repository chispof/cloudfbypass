#!/usr/bin/env python3
"""
CF Bypass Proxy - Bypasses Cloudflare JA3 fingerprint detection
================================================================
Architecture:
  Browser → Burp (8080) → Este proxy (8082) → Cloudflare (Chrome JA3)

Setup:
  1. Ejecutar: python3 cf_bypass_proxy.py
  2. Importar cf_bypass_ca.pem en Burp: Settings → Network → TLS → CA Certificates
  3. En Burp: Settings → Network → Connections → Upstream Proxy
     Host: 127.0.0.1  Port: 8082  Protocol: HTTP
  4. Navegar con el browser → Burp → este proxy → Cloudflare pasa el JA3 check
"""

import socket
import ssl
import threading
import select
import sys
import os
import datetime
import ipaddress
import struct
import tls_client as tls_lib

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ─── Config ────────────────────────────────────────────────────────────────────
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8082
CA_CERT_FILE = "cf_bypass_ca.pem"
CA_KEY_FILE  = "cf_bypass_ca.key"
TARGET_DOMAIN = "pichinchamiles.com"   # filtrar solo este dominio; "" = todos
TLS_PROFILE   = "chrome_120"          # perfil JA3 a impersonar
# ───────────────────────────────────────────────────────────────────────────────

_cert_cache = {}
_cert_lock  = threading.Lock()


# ── Generación de certificados ─────────────────────────────────────────────────

def generate_ca():
    """Genera CA raíz autofirmada para el proxy."""
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "CF Bypass Proxy CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Testing"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                key_encipherment=False, data_encipherment=False,
                content_commitment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    with open(CA_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(CA_KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    print(f"[+] CA generada → {CA_CERT_FILE}  (importar en Burp)")
    return cert, key


def load_or_create_ca():
    if os.path.exists(CA_CERT_FILE) and os.path.exists(CA_KEY_FILE):
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(CA_KEY_FILE, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        print(f"[*] CA cargada desde {CA_CERT_FILE}")
        return ca_cert, ca_key
    return generate_ca()


def get_cert_for_domain(domain, ca_cert, ca_key):
    """Genera (o devuelve desde caché) un cert TLS para el dominio dado."""
    with _cert_lock:
        if domain in _cert_cache:
            return _cert_cache[domain]

        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])
        san = x509.SubjectAlternativeName([x509.DNSName(domain)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=825))
            .add_extension(san, critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem  = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        tmp_cert = f"/tmp/proxy_cert_{domain}.pem"
        tmp_key  = f"/tmp/proxy_key_{domain}.pem"
        with open(tmp_cert, "wb") as f:
            f.write(cert_pem)
        with open(tmp_key, "wb") as f:
            f.write(key_pem)

        _cert_cache[domain] = (tmp_cert, tmp_key)
        return tmp_cert, tmp_key


# ── Sesión tls-client persistente (mantiene cookies de Cloudflare) ────────────
# Una sola sesión global por dominio para que cf_clearance persista entre requests

_sessions = {}
_sessions_lock = threading.Lock()

def get_session(host):
    """Devuelve sesión persistente para el host dado (mantiene cookies del challenge)."""
    domain = host.split(".")[-2] + "." + host.split(".")[-1] if "." in host else host
    with _sessions_lock:
        if domain not in _sessions:
            _sessions[domain] = tls_lib.Session(
                client_identifier=TLS_PROFILE,
                random_tls_extension_order=True,
            )
        return _sessions[domain]


# ── Core del proxy ─────────────────────────────────────────────────────────────

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# Headers que siempre se sobreescriben (Cloudflare los verifica)
OVERRIDE_HEADERS = {
    "User-Agent": CHROME_UA,
    "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Sec-CH-UA-Platform-Version": '"15.0.0"',
    "Sec-CH-UA-Arch": '"x86"',
    "Sec-CH-UA-Bitness": '"64"',
    "Sec-CH-UA-Full-Version": '"120.0.6099.130"',
    "Sec-CH-UA-Full-Version-List": (
        '"Not_A Brand";v="8.0.0.0", '
        '"Chromium";v="120.0.6099.130", '
        '"Google Chrome";v="120.0.6099.130"'
    ),
    "Sec-CH-UA-Model": '""',
}

# Headers que se agregan solo si no están presentes
# IMPORTANTE: NO incluir Sec-Fetch-* aquí — deben venir del browser real
# (navigate vs cors/same-origin — Cloudflare los verifica por tipo de request)
BROWSER_HEADERS = {
    "Accept-Language": "es-EC,es;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
}

# Headers que el proxy NO debe reenviar al servidor
HOP_BY_HOP = {
    "proxy-connection", "keep-alive", "transfer-encoding",
    "te", "trailers", "upgrade", "connection", "via",
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "forwarded",
}


def recv_line(sock):
    line = b""
    while not line.endswith(b"\r\n"):
        c = sock.recv(1)
        if not c:
            break
        line += c
    return line.decode("utf-8", errors="replace").strip()


def recv_headers(sock):
    headers = {}
    while True:
        line = recv_line(sock)
        if not line:
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


def recv_body(sock, headers):
    length = int(headers.get("content-length", 0))
    if length:
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data
    return b""


def build_response(status_code, status_text, headers, body):
    lines = [f"HTTP/1.1 {status_code} {status_text}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    lines.append("")
    header_bytes = "\r\n".join(lines).encode() + b"\r\n"
    return header_bytes + body


def forward_with_chrome_ja3(method, url, req_headers, body, session):
    """Reenvía la petición usando Chrome JA3 fingerprint."""
    # Construir headers limpios (sin hop-by-hop)
    clean_headers = {k: v for k, v in req_headers.items() if k.lower() not in HOP_BY_HOP}

    # Sobreescribir siempre con headers de Chrome (Cloudflare los verifica)
    for k, v in OVERRIDE_HEADERS.items():
        clean_headers[k] = v

    # Agregar headers faltantes sin sobreescribir los de Burp
    for k, v in BROWSER_HEADERS.items():
        if k.lower() not in {h.lower() for h in clean_headers}:
            clean_headers[k] = v

    m = method.upper()
    kwargs = dict(headers=clean_headers, allow_redirects=False)
    if body:
        kwargs["data"] = body

    # tls_client usa métodos individuales, no session.request()
    if   m == "GET":     return session.get(url, **kwargs)
    elif m == "POST":    return session.post(url, **kwargs)
    elif m == "PUT":     return session.put(url, **kwargs)
    elif m == "PATCH":   return session.patch(url, **kwargs)
    elif m == "DELETE":  return session.delete(url, **kwargs)
    elif m == "HEAD":    return session.head(url, **kwargs)
    elif m == "OPTIONS": return session.options(url, **kwargs)
    else:
        # fallback genérico
        return session.get(url, **kwargs)


def handle_https(client_sock, host, port, ca_cert, ca_key, session=None):
    """
    Maneja una conexión HTTPS:
    1. Termina el TLS de Burp usando cert firmado por nuestra CA
    2. Lee la petición HTTP plana
    3. La reenvía a Cloudflare con Chrome JA3
    """
    try:
        tmp_cert, tmp_key = get_cert_for_domain(host, ca_cert, ca_key)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=tmp_cert, keyfile=tmp_key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        ssl_sock = ctx.wrap_socket(client_sock, server_side=True)
    except ssl.SSLError as e:
        print(f"[!] TLS handshake fallido con {host}: {e}")
        return

    try:
        request_line = recv_line(ssl_sock)
        if not request_line:
            return

        parts = request_line.split(" ")
        if len(parts) < 3:
            return
        method, path, _ = parts[0], parts[1], parts[2]

        headers = recv_headers(ssl_sock)
        body    = recv_body(ssl_sock, headers)

        # Reconstruir URL completa
        if path.startswith("http"):
            url = path
        else:
            url = f"https://{host}:{port}{path}"

        # Usar sesión persistente para este host (mantiene cookies del challenge)
        host_session = get_session(host)

        print(f"[>] {method} {url}")
        resp = forward_with_chrome_ja3(method, url, headers, body, host_session)
        print(f"[<] {resp.status_code} {url}")

        # Log detallado en caso de 403 para diagnóstico
        if resp.status_code == 403:
            print(f"    [!] 403 headers de respuesta:")
            for k, v in resp.headers.items():
                print(f"        {k}: {v[:120]}")
            print(f"    [!] Headers enviados al servidor:")
            clean = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
            for k, v in OVERRIDE_HEADERS.items():
                clean[k] = v
            for k, v in clean.items():
                print(f"        {k}: {v[:100]}")

        # Limpiar headers de respuesta (NO quitar set-cookie — necesario para cf_clearance)
        resp_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in {"content-encoding", "transfer-encoding",
                                 "connection", "content-length"}
        }
        raw = build_response(
            resp.status_code,
            "OK",
            resp_headers,
            resp.content,
        )

        ssl_sock.sendall(raw)
    except Exception as e:
        print(f"[!] Error procesando {host}: {e}")
    finally:
        try:
            ssl_sock.close()
        except Exception:
            pass


def handle_http(method, path, client_headers, body, client_sock, session):
    """Maneja peticiones HTTP planas."""
    url = path if path.startswith("http") else f"http://{client_headers.get('host','')}{path}"
    try:
        resp = forward_with_chrome_ja3(method, url, client_headers, body, session)
        resp_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in {"content-encoding", "transfer-encoding",
                                  "connection", "content-length"}
        }
        raw = build_response(resp.status_code, "OK", resp_headers, resp.content)
        client_sock.sendall(raw)
    except Exception as e:
        print(f"[!] Error HTTP {url}: {e}")


def handle_client(client_sock, ca_cert, ca_key):
    try:
        request_line = recv_line(client_sock)
        if not request_line:
            return

        parts = request_line.split(" ")
        if len(parts) < 2:
            return

        method = parts[0].upper()

        if method == "CONNECT":
            # HTTPS tunnel
            target = parts[1]
            host, _, port_str = target.partition(":")
            port = int(port_str) if port_str else 443

            # IMPORTANTE: consumir los headers del CONNECT antes de responder
            # (si no, quedan en el buffer y rompen el TLS handshake)
            recv_headers(client_sock)

            # Confirmar tunnel establecido
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Terminar TLS de Burp y manejar petición
            handle_https(client_sock, host, port, ca_cert, ca_key)

        else:
            # HTTP plano
            path = parts[1]
            headers = recv_headers(client_sock)
            body    = recv_body(client_sock, headers)
            host_h  = headers.get("host", "")
            handle_http(method, path, headers, body, client_sock, get_session(host_h))

    except Exception as e:
        print(f"[!] handle_client error: {e}")
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


# ── Servidor ───────────────────────────────────────────────────────────────────

def run_proxy():
    ca_cert, ca_key = load_or_create_ca()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((PROXY_HOST, PROXY_PORT))
    srv.listen(50)

    print(f"""
╔══════════════════════════════════════════════════════╗
║        CF Bypass Proxy - Chrome JA3 Spoofer          ║
╠══════════════════════════════════════════════════════╣
║  Escuchando en : {PROXY_HOST}:{PROXY_PORT}                    ║
║  Perfil TLS   : {TLS_PROFILE}                        ║
║  Dominio      : {TARGET_DOMAIN or "todos"}                ║
╠══════════════════════════════════════════════════════╣
║  PASOS:                                              ║
║  1. Importar {CA_CERT_FILE} en Burp:          ║
║     Settings → Network → TLS → CA Certificates      ║
║  2. En Burp configurar upstream proxy:               ║
║     Settings → Network → Connections → Upstream      ║
║     Host: 127.0.0.1  Port: {PROXY_PORT}                    ║
╚══════════════════════════════════════════════════════╝
""")

    while True:
        try:
            client_sock, addr = srv.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, ca_cert, ca_key),
                daemon=True,
            )
            t.start()
        except KeyboardInterrupt:
            print("\n[*] Proxy detenido.")
            break
        except Exception as e:
            print(f"[!] Accept error: {e}")


if __name__ == "__main__":
    run_proxy()
