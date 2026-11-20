"""Emit the pure-Luau V7 decryptor.

The emitted code uses only ordinary globals that ``obf/format.py`` already
rewrites through the opaque alias table (``string``, ``table``, ``math``,
``bit32.bxor`` / ``band`` / ``bor``). Rotations/shifts are done with exact
double arithmetic, so no new alias path is needed and default builds stay
byte-compatible. There is no dynamic loader, no ``loadstring`` and no comments
beyond the required top banner.

The routines are:

* SHA-256, used only inside HMAC-SHA256.
* HMAC-SHA256, used as an encrypt-then-MAC tag verifier.
* ChaCha20, used as a stream cipher to recover the original byte payloads.
* DECRYPT(nonce, aad, tag, ciphertext) -> plaintext or nil.

The derived key is embedded. This is obfuscation, not confidentiality.
"""
from __future__ import annotations

import re

from .. import minify as _m
from ..crypto import CryptoPlan
from ..format import _GLOBAL_SKIP
from ..names import KEYWORDS as _KEYWORDS


_TEMPLATE = r'''local @KEY@ = @KEYLIT@
local @KCONST@ = {0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2}
local @WB@ = function(w, out)
  out[#out + 1] = string.char(math.floor(w / 16777216) % 256)
  out[#out + 1] = string.char(math.floor(w / 65536) % 256)
  out[#out + 1] = string.char(math.floor(w / 256) % 256)
  out[#out + 1] = string.char(w % 256)
end
local @WBLE@ = function(w, out)
  out[#out + 1] = string.char(w % 256)
  out[#out + 1] = string.char(math.floor(w / 256) % 256)
  out[#out + 1] = string.char(math.floor(w / 65536) % 256)
  out[#out + 1] = string.char(math.floor(w / 16777216) % 256)
end
local @RSHIFT@ = function(x, n)
  return math.floor(x / (2 ^ n)) % 0x100000000
end
local @ROTR@ = function(x, n)
  local p = 2 ^ n
  return (math.floor(x / p) + (x % p) * (0x100000000 / p)) % 0x100000000
end
local @LROT@ = function(x, n)
  local p = 2 ^ n
  return ((x * p) % 0x100000000 + math.floor(x / (0x100000000 / p))) % 0x100000000
end
local @BNOT@ = function(x)
  return 0xFFFFFFFF - x
end
local @SHA@ = function(msg)
  local n = #msg
  local bytes = {}
  for i = 1, n do bytes[i] = string.byte(msg, i) end
  bytes[n + 1] = 128
  local pad = (56 - ((n + 1) % 64)) % 64
  for i = 1, pad do bytes[n + 1 + i] = 0 end
  local total = n + 1 + pad + 8
  local bitlen = n * 8
  local hi = math.floor(bitlen / 0x100000000)
  local lo = bitlen % 0x100000000
  bytes[total - 7] = math.floor(hi / 16777216) % 256
  bytes[total - 6] = math.floor(hi / 65536) % 256
  bytes[total - 5] = math.floor(hi / 256) % 256
  bytes[total - 4] = hi % 256
  bytes[total - 3] = math.floor(lo / 16777216) % 256
  bytes[total - 2] = math.floor(lo / 65536) % 256
  bytes[total - 1] = math.floor(lo / 256) % 256
  bytes[total] = lo % 256
  local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
  local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  for start = 1, total, 64 do
    local w = {}
    for i = 0, 15 do
      local j = start + i * 4
      w[i + 1] = bytes[j] * 16777216 + bytes[j + 1] * 65536 + bytes[j + 2] * 256 + bytes[j + 3]
    end
    for i = 17, 64 do
      local x = w[i - 15]
      local y = w[i - 2]
      local s0 = bit32.bxor(bit32.bxor(@ROTR@(x, 7), @ROTR@(x, 18)), @RSHIFT@(x, 3))
      local s1 = bit32.bxor(bit32.bxor(@ROTR@(y, 17), @ROTR@(y, 19)), @RSHIFT@(y, 10))
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % 0x100000000
    end
    local a, b, c, d = h0, h1, h2, h3
    local e, f, g, h = h4, h5, h6, h7
    for i = 1, 64 do
      local S1 = bit32.bxor(bit32.bxor(@ROTR@(e, 6), @ROTR@(e, 11)), @ROTR@(e, 25))
      local ch = bit32.bxor(bit32.band(e, f), bit32.band(@BNOT@(e), g))
      local t1 = (h + S1 + ch + @KCONST@[i] + w[i]) % 0x100000000
      local S0 = bit32.bxor(bit32.bxor(@ROTR@(a, 2), @ROTR@(a, 13)), @ROTR@(a, 22))
      local maj = bit32.bxor(bit32.bxor(bit32.band(a, b), bit32.band(a, c)), bit32.band(b, c))
      local t2 = (S0 + maj) % 0x100000000
      h = g
      g = f
      f = e
      e = (d + t1) % 0x100000000
      d = c
      c = b
      b = a
      a = (t1 + t2) % 0x100000000
    end
    h0 = (h0 + a) % 0x100000000
    h1 = (h1 + b) % 0x100000000
    h2 = (h2 + c) % 0x100000000
    h3 = (h3 + d) % 0x100000000
    h4 = (h4 + e) % 0x100000000
    h5 = (h5 + f) % 0x100000000
    h6 = (h6 + g) % 0x100000000
    h7 = (h7 + h) % 0x100000000
  end
  local out = {}
  local words = {h0, h1, h2, h3, h4, h5, h6, h7}
  for i = 1, 8 do @WB@(words[i], out) end
  return table.concat(out)
end
local @LE32@ = function(s, i)
  return string.byte(s, i) + string.byte(s, i + 1) * 256 + string.byte(s, i + 2) * 65536 + string.byte(s, i + 3) * 16777216
end
local @QR@ = function(x, a, b, c, d)
  x[a] = (x[a] + x[b]) % 0x100000000
  x[d] = @LROT@(bit32.bxor(x[d], x[a]), 16)
  x[c] = (x[c] + x[d]) % 0x100000000
  x[b] = @LROT@(bit32.bxor(x[b], x[c]), 12)
  x[a] = (x[a] + x[b]) % 0x100000000
  x[d] = @LROT@(bit32.bxor(x[d], x[a]), 8)
  x[c] = (x[c] + x[d]) % 0x100000000
  x[b] = @LROT@(bit32.bxor(x[b], x[c]), 7)
end
local @BLOCK@ = function(kw, counter, nw)
  local st = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, kw[1], kw[2], kw[3], kw[4], kw[5], kw[6], kw[7], kw[8], counter, nw[1], nw[2], nw[3]}
  local x = {}
  for i = 1, 16 do x[i] = st[i] end
  for r = 1, 10 do
    @QR@(x, 1, 5, 9, 13)
    @QR@(x, 2, 6, 10, 14)
    @QR@(x, 3, 7, 11, 15)
    @QR@(x, 4, 8, 12, 16)
    @QR@(x, 1, 6, 11, 16)
    @QR@(x, 2, 7, 12, 13)
    @QR@(x, 3, 8, 9, 14)
    @QR@(x, 4, 5, 10, 15)
  end
  local out = {}
  for i = 1, 16 do @WBLE@((x[i] + st[i]) % 0x100000000, out) end
  return table.concat(out)
end
local @CHACHA@ = function(key, nonce, data)
  local kw = {}
  for i = 1, 8 do kw[i] = @LE32@(key, (i - 1) * 4 + 1) end
  local nw = {}
  for i = 1, 3 do nw[i] = @LE32@(nonce, (i - 1) * 4 + 1) end
  local out = {}
  local counter = 1
  local off = 0
  while off < #data do
    local block = @BLOCK@(kw, counter, nw)
    local take = 64
    if #data - off < 64 then take = #data - off end
    for j = 1, take do
      out[#out + 1] = string.char(bit32.bxor(string.byte(data, off + j), string.byte(block, j)))
    end
    off = off + 64
    counter = counter + 1
  end
  return table.concat(out)
end
local @HMAC@ = function(key, msg)
  if #key > 64 then key = @SHA@(key) end
  local ipad, opad = {}, {}
  for i = 1, 64 do
    local b = 0
    if i <= #key then b = string.byte(key, i) end
    ipad[i] = string.char(bit32.bxor(b, 0x36))
    opad[i] = string.char(bit32.bxor(b, 0x5c))
  end
  return @SHA@(table.concat(opad) .. @SHA@(table.concat(ipad) .. msg))
end
local @DECRYPT@ = function(nonce, aad, tag, ct)
  local want = @HMAC@(@KEY@, aad .. nonce .. ct)
  if #want ~= #tag then return nil end
  local diff = 0
  for i = 1, #tag do
    diff = diff + bit32.bxor(string.byte(want, i), string.byte(tag, i))
  end
  if diff ~= 0 then return nil end
  return @CHACHA@(@KEY@, nonce, ct)
end'''


def _expand_template() -> tuple[str, dict[str, str]]:
    """Give hard-coded locals long names and protect @PLACEHOLDER@ tokens.

    ``Names.new()`` emits one- or two-character identifiers. Prefixing every
    hard-coded local with ``v7_`` guarantees it cannot collide with a generated
    runtime name before ``format._rename_locals`` remaps the whole chunk.
    """
    text = _TEMPLATE
    sentinels: dict[str, str] = {}
    for name in set(re.findall(r"@([A-Z][A-Z0-9_]*)@", text)):
        sentinel = f"V7PH_{name}_END"
        sentinels[name] = sentinel
        text = text.replace(f"@{name}@", sentinel)

    toks = _m.tokenize(text.encode("utf-8"))
    out: list[_m.Tok] = []
    prev = None
    for t in toks:
        if t.kind == "ws" or t.kind == "comment":
            continue
        keep = False
        if t.kind == "name":
            name = t.text.decode("latin-1")
            member = prev is not None and prev.text in (b".", b":")
            keep = (
                member
                or name in _KEYWORDS
                or name in _GLOBAL_SKIP
                or name.startswith("V7PH_")
            )
            if not keep:
                t = _m.Tok("name", f"v7_{name}".encode("ascii"), t.start, t.end)
        if prev is not None and _m._need_space(prev, t):
            out.append(_m.Tok("ws", b" ", t.start, t.end))
        out.append(t)
        prev = t
    return b"".join(t.text for t in out).decode("latin-1"), sentinels


_EXPANDED_TEMPLATE, _SENTINELS = _expand_template()


def emit_crypto_lines(plan: CryptoPlan, ns) -> list[str]:
    """Assign fresh names and return Luau lines defining the decryptor."""
    r = plan.runtime
    r.key_var = ns.fresh_runtime("K")
    r.hmac_var = ns.fresh_runtime("H")
    r.chacha_var = ns.fresh_runtime("C")
    r.decrypt_var = ns.fresh_runtime("D")
    r.sha_var = ns.fresh_runtime("S")
    r.block_var = ns.fresh_runtime("B")
    r.qr_var = ns.fresh_runtime("Q")
    r.le32_var = ns.fresh_runtime("L")
    r.wb_var = ns.fresh_runtime("W")
    r.wble_var = ns.fresh_runtime("W")
    r.kconst_var = ns.fresh_runtime("K")
    r.rotr_var = ns.fresh_runtime("R")
    r.lrot_var = ns.fresh_runtime("L")
    r.rshift_var = ns.fresh_runtime("R")
    r.bnot_var = ns.fresh_runtime("B")

    values = {
        "KEY": r.key_var,
        "KCONST": r.kconst_var,
        "WB": r.wb_var,
        "WBLE": r.wble_var,
        "RSHIFT": r.rshift_var,
        "ROTR": r.rotr_var,
        "LROT": r.lrot_var,
        "BNOT": r.bnot_var,
        "SHA": r.sha_var,
        "LE32": r.le32_var,
        "QR": r.qr_var,
        "BLOCK": r.block_var,
        "CHACHA": r.chacha_var,
        "HMAC": r.hmac_var,
        "DECRYPT": r.decrypt_var,
        "KEYLIT": plan.key_literal,
    }
    text = _EXPANDED_TEMPLATE
    for name, value in values.items():
        sentinel = _SENTINELS[name]
        text = text.replace(sentinel, value)
    if any(sentinel in text for sentinel in _SENTINELS.values()):
        raise RuntimeError("unresolved crypto runtime placeholder")
    if any(f"@{name}@" in text for name in _SENTINELS):
        raise RuntimeError("unresolved @PLACEHOLDER@ token")
    return text.splitlines()
