# ffl-gnutls

Focused native bindings over **GnuTLS** for the exact cryptographic operations FastFileLink needs.
The reference source version is **GnuTLS 3.8.13**; the native core requires GnuTLS **>= 3.8.4** because RSA-OAEP support entered the public API in 3.8.4.

This is intentionally not a replacement for `python-gnutls`. It exposes only:

- secure random bytes
- ECDSA P-384 key generation, SHA-256 sign and verify
- P-384 ECDH
- HKDF-SHA256
- AES-CBC with PKCS#7 padding
- AES-GCM with a 16-byte authentication tag
- RSA key generation
- RSA-OAEP with SHA-256
- RSA public/private PEM normalization
- RSA private-key PKCS#8 serialization

## Layers

```text
FastFileLink GnuTLS.py
        |
        v
ffl_gnutls.CryptoEngine
        |
        v
_ffl_gnutls (CPython adapter)
        |
        v
crypto_core.c
        |
        v
GnuTLS 3.8.x -> Nettle / GMP
```

The C core has no Python knowledge. The CPython adapter only converts arguments/results, releases the GIL, and translates errors. The OO facade owns Python type validation. FastFileLink's `GnuTLS.py` owns protocol-specific composition such as ECIES payload layout and the existing voucher pre-hash.

## Build against an existing GnuTLS

```bash
python -m pip install build
python -m build --wheel
```

By default CMake uses `pkg-config gnutls>=3.8.4`.

For a dedicated prefix:

```bash
CMAKE_ARGS="-DFFL_GNUTLS_PROVIDER=prefix -DFFL_GNUTLS_ROOT=/opt/gnutls" \
python -m build --wheel
```

For a fully static wheel, point the prefix at a static GnuTLS installation and add:

```bash
-DFFL_GNUTLS_STATIC=ON
```

That consumes `pkg-config --static` metadata, so the same Nettle/GMP dependencies already belonging to that GnuTLS build are linked rather than duplicated by this project.

## GnuTLS 3.8.13 source pin

`scripts/bootstrap.py` downloads and verifies the official GnuTLS 3.8.13 source archive. It intentionally does not vendor Nettle or GMP; use your existing platform/superconfigure dependencies when building GnuTLS.

## FastFileLink migration

`integration/GnuTLS.py` is the thin `CryptoBackend` replacement for the previous `MbedTLS.py` implementation. It removes all `python-mbedtls` dependencies.

## Tests

```bash
python -m pip install -e ".[dev]"
pytest -q
```

The tests exercise the native extension: P-384 signing/ECDH, RFC5869 HKDF, AES-GCM/CBC, RSA-OAEP, and PKCS#8 serialization.
