l#!/usr/bin/env python3
"""
Vercel Python (ASGI/Starlette) - VLESS + Trojan + VMess AEAD over WebSocket
Deploy target: api/index.py
"""

import os
import sys
import time
import hmac
import json
import base64
import struct
import hashlib
import secrets
import socket
import zlib
from urllib.parse import quote

import httpx
from starlette.applications import Starlette
from starlette.routing import Route, WebSocketRoute
from starlette.responses import Response, PlainTextResponse, HTMLResponse
from starlette.websockets import WebSocket, WebSocketDisconnect

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ========================== Environment ==========================
UUID = os.environ.get('UUID', 'd1cf4b9c-3e57-085d-b34a-797fcf601381')
SUB_PATH = os.environ.get('SUB_PATH', 'vercel')
NAME = os.environ.get('NAME', 'Vercel-Node')
PORT = int(os.environ.get('PORT', 3000))
SHOW_LOG = bool(os.environ.get('SHOW_LOG'))

# true = terima UUID random untuk VLESS/Trojan (+ UUID env)
ALLOW_ANY_UUID = os.environ.get('ALLOW_ANY_UUID', 'true').lower() in ('1', 'true', 'yes')

def log(*a):
    if SHOW_LOG: print(*a, flush=True)

def log_err(*a):
    if SHOW_LOG: print(*a, file=sys.stderr, flush=True)

UUID_CLEAN = UUID.replace('-', '')
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]
import re
IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# ==================== Utility ====================
def is_blocked_domain(host):
    if not host: return False
    h = host.lower()
    return any(h == b or h.endswith('.' + b) for b in BLOCKED_DOMAINS)

def utf8(s): return s.encode('utf-8') if isinstance(s, str) else bytes(s)
def md5(d): return hashlib.md5(bytes(d)).digest()
def sha256(d): return hashlib.sha256(bytes(d)).digest()
def hmac_sha256(k, d): return hmac.new(bytes(k), bytes(d), hashlib.sha256).digest()
def crc32(d): return zlib.crc32(bytes(d)) & 0xffffffff

def fnv1a32(data):
    h = 0x811c9dc5
    for b in bytes(data):
        h ^= b
        h = (h * 0x01000193) & 0xffffffff
    return h

def uuid_to_bytes(text):
    s = str(text or '').strip().lower().replace('-', '')
    return bytes.fromhex(s)

# ==================== VMess KDF ====================
def hmac_with_hash(hash_fn, key, data):
    k = bytes(key)
    if len(k) > 64: k = hash_fn(k)
    kb = (k + b'\x00' * 64)[:64]
    ipad = bytes(b ^ 0x36 for b in kb)
    opad = bytes(b ^ 0x5c for b in kb)
    return hash_fn(opad + hash_fn(ipad + bytes(data)))

def vmess_kdf(key, *path_parts):
    def make_fn(prev, path):
        pb = utf8(path)
        return lambda data: hmac_with_hash(prev, pb, data)
    fn = lambda data: hmac_sha256(b'VMess AEAD KDF', data)
    for p in path_parts:
        fn = make_fn(fn, p)
    return fn(bytes(key))

def vmess_kdf16(key, *p): return vmess_kdf(key, *p)[:16]
def vmess_cmd_key(u): return md5(bytes(u) + b'c48619fe-8f02-49e0-b9e9-edf763e17e21')

# ==================== Crypto Constants ====================
VMESS_SECURITY_AES128_GCM = 3
VMESS_SECURITY_CHACHA20_POLY1305 = 4
VMESS_SECURITY_NONE = 5
VMESS_SECURITY_ZERO = 6

VMESS_OPT_CHUNK_STREAM = 0x01
VMESS_OPT_CHUNK_MASKING = 0x04
VMESS_OPT_GLOBAL_PADDING = 0x08
VMESS_OPT_AUTHENTICATED_LENGTH = 0x10

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x02
ATYP_IPV6 = 0x03
CMD_TCP = 0x01
CMD_MUX = 0x03

KDF_AUTH_ID      = b'AES Auth ID Encryption'
KDF_HDR_LEN_KEY  = b'VMess Header AEAD Key_Length'
KDF_HDR_LEN_IV   = b'VMess Header AEAD Nonce_Length'
KDF_HDR_KEY      = b'VMess Header AEAD Key'
KDF_HDR_IV       = b'VMess Header AEAD Nonce'
KDF_RESP_LEN_KEY = b'AEAD Resp Header Len Key'
KDF_RESP_LEN_IV  = b'AEAD Resp Header Len IV'
KDF_RESP_KEY     = b'AEAD Resp Header Key'
KDF_RESP_IV      = b'AEAD Resp Header IV'
KDF_AUTH_LEN     = b'auth_len'

def chacha_key(k16):
    a = md5(k16); return a + md5(a)

def normalize_aead_key(sec, key):
    k = bytes(key)
    return chacha_key(k) if sec == VMESS_SECURITY_CHACHA20_POLY1305 else k[:16]

def _aead(sec, key):
    kb = normalize_aead_key(sec, key)
    if sec == VMESS_SECURITY_AES128_GCM: return AESGCM(kb)
    if sec == VMESS_SECURITY_CHACHA20_POLY1305: return ChaCha20Poly1305(kb)
    raise ValueError(f'Security {sec} not AEAD')

def aead_seal(sec, key, nonce, plain, aad=None):
    return _aead(sec, key).encrypt(bytes(nonce), bytes(plain), bytes(aad) if aad else None)

def aead_open(sec, key, nonce, sealed, aad=None):
    return _aead(sec, key).decrypt(bytes(nonce), bytes(sealed), bytes(aad) if aad else None)

def aes_ecb_decrypt_block(key, block):
    c = Cipher(algorithms.AES(bytes(key)), modes.ECB()).decryptor()
    return c.update(bytes(block)) + c.finalize()

# ==================== SHAKE128 ====================
KECCAK64_MASK = (1 << 64) - 1
KECCAK_ROTC = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14]
KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

def rotl64(v, s):
    n = s & 63
    return (v & KECCAK64_MASK) if n == 0 else (((v << n) | (v >> (64 - n))) & KECCAK64_MASK)

def keccak_f1600(st):
    c = [0]*5; d = [0]*5; b = [0]*25
    for rc in KECCAK_RC:
        for x in range(5):
            c[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20]
        for x in range(5):
            d[x] = c[(x+4)%5] ^ rotl64(c[(x+1)%5], 1)
        for y in range(5):
            for x in range(5):
                st[x+5*y] = (st[x+5*y] ^ d[x]) & KECCAK64_MASK
        for y in range(5):
            for x in range(5):
                src = x + 5*y
                b[y + 5*((2*x + 3*y) % 5)] = rotl64(st[src], KECCAK_ROTC[src])
        for y in range(5):
            r = 5*y
            for x in range(5):
                st[r+x] = (b[r+x] ^ ((~b[r+((x+1)%5)]) & b[r+((x+2)%5)])) & KECCAK64_MASK
        st[0] = (st[0] ^ rc) & KECCAK64_MASK

class Shake128Xof:
    def __init__(self, data):
        self.rate = 168
        self.state = [0]*25
        self.squeeze_offset = 0
        self._absorb(bytes(data))
    def _xor_block(self, blk):
        for i, byte in enumerate(blk):
            self.state[i >> 3] ^= byte << ((i & 7) * 8)
    def _absorb(self, data):
        off = 0
        while len(data) - off >= self.rate:
            self._xor_block(data[off:off+self.rate])
            keccak_f1600(self.state)
            off += self.rate
        fb = bytearray(self.rate)
        rem = data[off:]
        fb[:len(rem)] = rem
        fb[len(rem)] ^= 0x1f
        fb[self.rate - 1] ^= 0x80
        self._xor_block(fb)
        keccak_f1600(self.state)
    def read(self, n):
        out = bytearray(n)
        for i in range(n):
            if self.squeeze_offset == self.rate:
                keccak_f1600(self.state); self.squeeze_offset = 0
            p = self.squeeze_offset; self.squeeze_offset += 1
            out[i] = (self.state[p >> 3] >> ((p & 7) * 8)) & 0xff
        return bytes(out)

class ShakeSizeParser:
    def __init__(self, seed): self.shake = Shake128Xof(seed)
    def _nw(self): b = self.shake.read(2); return (b[0] << 8) | b[1]
    def decode_size(self, data):
        b = bytes(data); return (((b[0] << 8) | b[1]) ^ self._nw()) & 0xffff
    def encode_size(self, size):
        v = (size ^ self._nw()) & 0xffff; return bytes([v >> 8, v & 0xff])
    def next_padding_len(self): return self._nw() % 64

class NonceCounter:
    def __init__(self, iv): self.base = bytes(iv); self.count = 0
    def next(self, size=12):
        out = bytearray(self.base)
        out[0] = (self.count >> 8) & 0xff; out[1] = self.count & 0xff
        self.count = (self.count + 1) & 0xffff
        return bytes(out[:size])

# ==================== VMess Header Parse ====================
def try_parse_port_first_address(data, cur, atyp):
    b = bytes(data)
    if atyp == ATYP_IPV4:
        if len(b) < cur + 4: return None
        return '.'.join(str(x) for x in b[cur:cur+4]), cur + 4
    if atyp == ATYP_DOMAIN:
        if len(b) < cur + 1: return None
        L = b[cur]; cur += 1
        if not L or len(b) < cur + L: return None
        return b[cur:cur+L].decode('utf-8', errors='replace'), cur + L
    if atyp == ATYP_IPV6:
        if len(b) < cur + 16: return None
        parts = [f'{struct.unpack(">H", b[cur+i:cur+i+2])[0]:x}' for i in range(0, 16, 2)]
        return ':'.join(parts), cur + 16
    raise ValueError(f'invalid atyp {atyp}')

def try_parse_vmess_header(data, uuid_bytes, now_sec=None):
    if now_sec is None: now_sec = int(time.time())
    b = bytes(data)
    if len(b) < 16: return None
    cmd_key = vmess_cmd_key(uuid_bytes)
    auth_id = b[:16]
    try:
        auth_plain = aes_ecb_decrypt_block(vmess_kdf16(cmd_key, KDF_AUTH_ID), auth_id)
    except Exception: return None
    if len(auth_plain) < 16: return None
    ts = struct.unpack('>q', auth_plain[0:8])[0]
    if crc32(auth_plain[0:12]) != struct.unpack('>I', auth_plain[12:16])[0]: return None
    if abs(ts - now_sec) > 120: return None
    if len(b) < 42: return None
    enc_len = b[16:34]; conn_nonce = b[34:42]
    try:
        lp = aead_open(VMESS_SECURITY_AES128_GCM,
                       vmess_kdf16(cmd_key, KDF_HDR_LEN_KEY, auth_id, conn_nonce),
                       vmess_kdf(cmd_key, KDF_HDR_LEN_IV, auth_id, conn_nonce)[:12],
                       enc_len, auth_id)
    except Exception: return None
    plain_len = (lp[0] << 8) | lp[1]
    total = 42 + plain_len + 16
    if len(b) < total: return None
    try:
        plain = aead_open(VMESS_SECURITY_AES128_GCM,
                          vmess_kdf16(cmd_key, KDF_HDR_KEY, auth_id, conn_nonce),
                          vmess_kdf(cmd_key, KDF_HDR_IV, auth_id, conn_nonce)[:12],
                          b[42:total], auth_id)
    except Exception: return None
    rbi = plain[1:17]; rbk = plain[17:33]
    resp_hdr = plain[33]; option = plain[34]
    wire_sec = plain[35] & 0x0f; command = plain[37]
    security = wire_sec
    if security == VMESS_SECURITY_ZERO:
        security = VMESS_SECURITY_NONE
        option &= ~(VMESS_OPT_CHUNK_STREAM | VMESS_OPT_CHUNK_MASKING |
                    VMESS_OPT_GLOBAL_PADDING | VMESS_OPT_AUTHENTICATED_LENGTH)
    p = 38
    address = 'v1.mux.cool'; port = 0; atyp = ATYP_DOMAIN
    if command != CMD_MUX:
        port = (plain[p] << 8) | plain[p+1]; p += 2
        atyp = plain[p]; p += 1
        r = try_parse_port_first_address(plain, p, atyp)
        if not r: raise ValueError('truncated destination')
        address, p = r
    cp = len(plain) - 4
    if fnv1a32(plain[:cp]) != struct.unpack('>I', plain[cp:cp+4])[0]:
        raise ValueError('invalid VMess checksum')
    return {
        'command': command, 'address': address, 'port': port,
        'address_type': atyp, 'option': option,
        'security': security, 'wire_security': wire_sec,
        'request_body_iv': rbi, 'request_body_key': rbk,
        'response_header': resp_hdr, 'header_length': total, 'auth_id': auth_id,
        'response_body_key': sha256(rbk)[:16],
        'response_body_iv': sha256(rbi)[:16],
    }

# ==================== VMess Body Decoder / Encoder ====================
class VmessBodyDecoder:
    def __init__(self, h):
        self.h = h; self.pending = b''; self.awaiting = None; self.done = False
        self.zero_raw = (h['wire_security'] == VMESS_SECURITY_ZERO or
                         (h['security'] == VMESS_SECURITY_NONE and not (h['option'] & VMESS_OPT_CHUNK_STREAM)))
        self.size_shake = ShakeSizeParser(h['request_body_iv']) if (h['option'] & VMESS_OPT_CHUNK_MASKING) else None
        self.padding_shake = self.size_shake if (h['option'] & VMESS_OPT_GLOBAL_PADDING) else None
        self.body_nonce = NonceCounter(h['request_body_iv'])
        self.length_nonce = NonceCounter(h['request_body_iv'])
        self.auth_length = bool(h['option'] & VMESS_OPT_AUTHENTICATED_LENGTH) and \
                           h['security'] in (VMESS_SECURITY_AES128_GCM, VMESS_SECURITY_CHACHA20_POLY1305)
        self.auth_length_key = vmess_kdf16(h['request_body_key'], KDF_AUTH_LEN) if self.auth_length else None
    def push(self, chunk):
        if self.done: return []
        c = bytes(chunk)
        if self.zero_raw: return [c] if c else []
        self.pending += c
        out = []
        while True:
            if not self.awaiting:
                sb_len = 18 if self.auth_length else 2
                if len(self.pending) < sb_len: break
                padding = 0
                if self.padding_shake and self.h['security'] != VMESS_SECURITY_NONE:
                    padding = self.padding_shake.next_padding_len()
                raw = self.pending[:sb_len]
                if self.auth_length:
                    pl = aead_open(self.h['security'], self.auth_length_key, self.length_nonce.next(12), raw)
                    size = ((pl[0] << 8) | pl[1]) + 16
                elif self.size_shake:
                    size = self.size_shake.decode_size(raw)
                else:
                    size = (raw[0] << 8) | raw[1]
                self.pending = self.pending[sb_len:]
                self.awaiting = (size, padding)
            size, padding = self.awaiting
            if len(self.pending) < size: break
            frame = self.pending[:size]; self.pending = self.pending[size:]; self.awaiting = None
            if self.h['security'] == VMESS_SECURITY_NONE:
                if size == 0: self.done = True; break
                out.append(frame); continue
            if size == 16 + padding: self.done = True; break
            sealed = frame[:size - padding]
            out.append(aead_open(self.h['security'], self.h['request_body_key'], self.body_nonce.next(12), sealed))
        return out

class VmessBodyEncoder:
    def __init__(self, h):
        self.h = h
        self.response_key = h['response_body_key']; self.response_iv = h['response_body_iv']
        self.zero_raw = (h['wire_security'] == VMESS_SECURITY_ZERO or
                         (h['security'] == VMESS_SECURITY_NONE and not (h['option'] & VMESS_OPT_CHUNK_STREAM)))
        self.size_shake = ShakeSizeParser(self.response_iv) if (h['option'] & VMESS_OPT_CHUNK_MASKING) else None
        self.padding_shake = self.size_shake if (h['option'] & VMESS_OPT_GLOBAL_PADDING) else None
        self.body_nonce = NonceCounter(self.response_iv)
        self.length_nonce = NonceCounter(h['request_body_iv'])
        self.auth_length = bool(h['option'] & VMESS_OPT_AUTHENTICATED_LENGTH) and \
                           h['security'] in (VMESS_SECURITY_AES128_GCM, VMESS_SECURITY_CHACHA20_POLY1305)
        self.auth_length_key = vmess_kdf16(h['request_body_key'], KDF_AUTH_LEN) if self.auth_length else None
    def encode(self, data):
        d = bytes(data)
        if self.zero_raw: return d
        return b''.join(self._unit(d[o:o+8192]) for o in range(0, len(d), 8192))
    def _unit(self, p):
        p = bytes(p)
        if self.h['security'] == VMESS_SECURITY_NONE:
            size = len(p)
            sb = self.size_shake.encode_size(size) if self.size_shake else bytes([size >> 8, size & 0xff])
            return sb + p
        padding = self.padding_shake.next_padding_len() if self.padding_shake else 0
        sealed = aead_seal(self.h['security'], self.response_key, self.body_nonce.next(12), p)
        size = len(sealed) + padding
        if self.auth_length:
            ps = size - 16
            sb = aead_seal(self.h['security'], self.auth_length_key, self.length_nonce.next(12),
                           bytes([ps >> 8, ps & 0xff]))
        elif self.size_shake:
            sb = self.size_shake.encode_size(size)
        else:
            sb = bytes([size >> 8, size & 0xff])
        return sb + sealed + secrets.token_bytes(padding)

def encode_vmess_response_header(h):
    plain = bytes([h['response_header'], 0, 0, 0])
    len_plain = bytes([0, len(plain)])
    len_key = vmess_kdf16(h['response_body_key'], KDF_RESP_LEN_KEY)
    len_iv = vmess_kdf(h['response_body_iv'], KDF_RESP_LEN_IV)[:12]
    pl_key = vmess_kdf16(h['response_body_key'], KDF_RESP_KEY)
    pl_iv = vmess_kdf(h['response_body_iv'], KDF_RESP_IV)[:12]
    return (aead_seal(VMESS_SECURITY_AES128_GCM, len_key, len_iv, len_plain) +
            aead_seal(VMESS_SECURITY_AES128_GCM, pl_key, pl_iv, plain))

# ==================== HTTP Helpers ====================
_http = None
def get_http():
    global _http
    if _http is None:
        _http = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    return _http

async def resolve_host(host):
    if IPV4_REGEX.match(host): return host
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        info = await asyncio.wait_for(loop.getaddrinfo(host, None, family=socket.AF_INET), timeout=4)
        if info: return info[0][4][0]
    except Exception: pass
    try:
        r = await get_http().get(f'https://dns.google/resolve?name={quote(host)}&type=A',
                                 headers={'Accept': 'application/dns-json'})
        d = r.json()
        if d.get('Status') == 0:
            for a in d.get('Answer', []):
                if a.get('type') == 1: return a['data']
    except Exception: pass
    return host

async def get_isp():
    try:
        r = await get_http().get('https://api.ip.sb/geoip', headers={'User-Agent': 'Mozilla/5.0'})
        d = r.json()
        return f"{d['country_code']}-{d['isp']}".replace(' ', '_')
    except Exception: pass
    try:
        r = await get_http().get('http://ip-api.com/json', headers={'User-Agent': 'Mozilla/5.0'})
        d = r.json()
        return f"{d['countryCode']}-{d['org']}".replace(' ', '_')
    except Exception:
        return 'Unknown'

def get_endpoint_info(request):
    raw = (request.headers.get('x-forwarded-host') or request.headers.get('host') or 'localhost').split(',')[0].strip()
    proto = (request.headers.get('x-forwarded-proto') or '').split(',')[0].strip().lower()
    is_tls = proto == 'https' or request.url.scheme == 'https'
    hostname = raw; port_hdr = None
    idx = raw.rfind(':')
    if idx > -1 and raw[idx+1:].isdigit():
        hostname = raw[:idx]; port_hdr = int(raw[idx+1:])
    if hostname.startswith('[') and hostname.endswith(']'):
        hostname = hostname[1:-1]
    port = port_hdr or (443 if is_tls else (PORT or 80))
    return hostname or 'localhost', port, ('tls' if is_tls else 'none')

# ==================== WebSocket Bridge ====================
async def _ws_to_tcp(ws, reader, writer, decoder=None):
    try:
        while True:
            try: data = await ws.receive_bytes()
            except WebSocketDisconnect: break
            if decoder:
                for plain in decoder.push(data): writer.write(plain)
            else:
                writer.write(data)
            await writer.drain()
    except Exception as e:
        log_err(f'[WS→TCP] {e}')

async def _tcp_to_ws(ws, reader, writer, encoder=None):
    try:
        while True:
            data = await reader.read(8192)
            if not data: break
            payload = encoder.encode(data) if encoder else data
            if payload: await ws.send_bytes(payload)
    except Exception as e:
        log_err(f'[TCP→WS] {e}')

async def bridge(ws, reader, writer, decoder=None, encoder=None):
    import asyncio
    t1 = asyncio.create_task(_ws_to_tcp(ws, reader, writer, decoder))
    t2 = asyncio.create_task(_tcp_to_ws(ws, reader, writer, encoder))
    try:
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            if not t.done(): t.cancel()
        try: writer.close(); await writer.wait_closed()
        except Exception: pass

# ==================== VLESS ====================
async def handle_vless(ws, msg):
    if len(msg) < 18: return False
    version = msg[0]; client_uuid = bytes(msg[1:17])
    if not ALLOW_ANY_UUID and client_uuid != uuid_to_bytes(UUID_CLEAN): return False
    i = 18 + msg[17] + 1
    if len(msg) < i + 3: return False
    port = struct.unpack('>H', msg[i:i+2])[0]; i += 2
    atyp = msg[i]; i += 1
    if atyp == 1:
        if len(msg) < i + 4: return False
        host = '.'.join(str(b) for b in msg[i:i+4]); i += 4
    elif atyp == 2:
        if len(msg) < i + 1: return False
        L = msg[i]; i += 1
        if len(msg) < i + L: return False
        host = msg[i:i+L].decode('utf-8', errors='replace'); i += L
    elif atyp == 3:
        if len(msg) < i + 16: return False
        host = ':'.join(f'{struct.unpack(">H", msg[i+j:i+j+2])[0]:x}' for j in range(0, 16, 2)); i += 16
    else: return False
    if is_blocked_domain(host): return False
    try: await ws.send_bytes(bytes([version, 0]))
    except Exception: return False
    target = await resolve_host(host)
    import asyncio
    try: reader, writer = await asyncio.open_connection(target, port)
    except Exception: return False
    if i < len(msg):
        writer.write(msg[i:]); await writer.drain()
    await bridge(ws, reader, writer)
    return True

# ==================== Trojan ====================
async def handle_trojan(ws, msg):
    if len(msg) < 58: return False
    received = msg[:56].decode('ascii', errors='replace')
    if not ALLOW_ANY_UUID:
        if received != hashlib.sha224(UUID.encode()).hexdigest(): return False
    off = 56
    if off + 1 < len(msg) and msg[off] == 0x0d and msg[off+1] == 0x0a: off += 2
    if off >= len(msg) or msg[off] != 0x01: return False
    off += 1
    if off >= len(msg): return False
    atyp = msg[off]; off += 1
    if atyp == 0x01:
        if len(msg) < off + 4: return False
        host = '.'.join(str(b) for b in msg[off:off+4]); off += 4
    elif atyp == 0x03:
        if len(msg) < off + 1: return False
        L = msg[off]; off += 1
        if len(msg) < off + L: return False
        host = msg[off:off+L].decode('utf-8', errors='replace'); off += L
    elif atyp == 0x04:
        if len(msg) < off + 16: return False
        host = ':'.join(f'{struct.unpack(">H", msg[off+j:off+j+2])[0]:x}' for j in range(0, 16, 2)); off += 16
    else: return False
    if len(msg) < off + 2: return False
    port = struct.unpack('>H', msg[off:off+2])[0]; off += 2
    if off + 1 < len(msg) and msg[off] == 0x0d and msg[off+1] == 0x0a: off += 2
    if is_blocked_domain(host): return False
    target = await resolve_host(host)
    import asyncio
    try: reader, writer = await asyncio.open_connection(target, port)
    except Exception: return False
    if off < len(msg):
        writer.write(msg[off:]); await writer.drain()
    await bridge(ws, reader, writer)
    return True

# ==================== VMess ====================
async def handle_vmess(ws, msg):
    try: header = try_parse_vmess_header(msg, uuid_to_bytes(UUID_CLEAN))
    except Exception as e:
        log_err(f'[VMESS PARSE] {e}'); return False
    if not header: return False
    if is_blocked_domain(header['address']): return False
    remainder = msg[header['header_length']:]
    decoder = VmessBodyDecoder(header); encoder = VmessBodyEncoder(header)
    try: await ws.send_bytes(encode_vmess_response_header(header))
    except Exception: return False
    target = await resolve_host(header['address'])
    import asyncio
    try: reader, writer = await asyncio.open_connection(target, header['port'])
    except Exception: return False
    if remainder:
        try:
            for plain in decoder.push(remainder): writer.write(plain)
            await writer.drain()
        except Exception: 
            try: writer.close()
            except Exception: pass
            return False
    await bridge(ws, reader, writer, decoder, encoder)
    return True

# ==================== WebSocket Router ====================
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    path = ws.url.path
    try:
        msg = await ws.receive_bytes()
    except Exception:
        await ws.close(); return
    try:
        if path == '/vless':  ok = await handle_vless(ws, msg)
        elif path == '/trojan': ok = await handle_trojan(ws, msg)
        elif path == '/vmess':  ok = await handle_vmess(ws, msg)
        else: ok = False
        if not ok:
            await ws.close()
    except Exception as e:
        log_err(f'[DISPATCH] {e}')
        try: await ws.close()
        except Exception: pass

# ==================== HTTP Endpoints ====================
async def build_subscription(request):
    isp = await get_isp()
    domain, _, _ = get_endpoint_info(request)
    name_part = f"{NAME}-{isp}" if NAME else isp
    vless = (f"vless://{UUID}@{domain}:443?path=%2Fvless&security=tls"
             f"&encryption=none&host={domain}&fp=chrome&type=ws&sni={domain}#{name_part}-VLESS")
    trojan = (f"trojan://{UUID}@{domain}:443?path=%2Ftrojan&security=tls"
              f"&host={domain}&fp=chrome&type=ws&sni={domain}#{name_part}-Trojan")
    vmess_cfg = {
        'v':'2','ps':f'{name_part}-VMess','add':domain,'port':'443','id':UUID,'aid':'0',
        'scy':'auto','net':'ws','type':'none','host':domain,'path':'/vmess',
        'tls':'tls','sni':domain,'alpn':'','fp':'chrome',
    }
    vmess = 'vmess://' + base64.b64encode(json.dumps(vmess_cfg, separators=(',', ':')).encode()).decode()
    return '\n'.join([vless, trojan, vmess])

async def sub_endpoint(request):
    try:
        sub = await build_subscription(request)
        return PlainTextResponse(base64.b64encode(sub.encode()).decode() + '\n',
                                 headers={'Access-Control-Allow-Origin': '*'})
    except Exception as e:
        log_err(f'[SUB] {e}')
        return PlainTextResponse('Internal Server Error\n', status_code=500)

async def index_endpoint(request):
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        idx = os.path.join(here, '..', 'index.html')
        with open(idx, 'r', encoding='utf-8') as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse('<h3>Node Proxy UI Running. Subscriptions ready at /vercel</h3>')

# ==================== App ====================
routes = [
    WebSocketRoute('/vless', ws_endpoint),
    WebSocketRoute('/trojan', ws_endpoint),
    WebSocketRoute('/vmess', ws_endpoint),
    Route(f'/{SUB_PATH}', sub_endpoint),
    Route('/vercel', sub_endpoint),
    Route('/sub', sub_endpoint),
    Route('/', index_endpoint),
    Route('/index.html', index_endpoint),
]
app = Starlette(routes=routes)
