import ffl_gnutls


def testVersionIsSupported():
    version = tuple(int(part) for part in ffl_gnutls.CryptoEngine().version.split(".")[:3])
    assert version >= (3, 8, 4)


def testP384SignVerifyAndPublicDerivation():
    engine = ffl_gnutls.CryptoEngine()
    privateKeyDER, publicKeyDER = engine.generateP384KeyPair()
    assert engine.deriveP384PublicKey(privateKeyDER) == publicKeyDER
    signature = engine.signSHA256(b"ffl-gnutls", privateKeyDER)
    assert engine.verifySHA256(b"ffl-gnutls", signature, publicKeyDER)
    assert not engine.verifySHA256(b"different", signature, publicKeyDER)


def testP384ECDHAgreement():
    engine = ffl_gnutls.CryptoEngine()
    privateKeyA, publicKeyA = engine.generateP384KeyPair()
    privateKeyB, publicKeyB = engine.generateP384KeyPair()
    sharedA = engine.deriveP384SharedSecret(privateKeyA, publicKeyB)
    sharedB = engine.deriveP384SharedSecret(privateKeyB, publicKeyA)
    assert len(sharedA) == 48
    assert sharedA == sharedB


def testHKDFRFC5869CaseOne():
    engine = ffl_gnutls.CryptoEngine()
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    assert engine.deriveHKDFSHA256(ikm, 42, info, salt) == expected


def testAESGCMRoundTrip():
    engine = ffl_gnutls.CryptoEngine()
    key = bytes(range(32)); nonce = bytes(range(12)); aad = b"header"; plaintext = b"native AES-GCM payload"
    ciphertext = engine.encryptAESGCM(key, plaintext, nonce, aad)
    assert len(ciphertext) == len(plaintext) + 16
    assert engine.decryptAESGCM(key, nonce, ciphertext, aad) == plaintext


def testAESCBCRoundTrip():
    engine = ffl_gnutls.CryptoEngine()
    key = bytes(range(32)); iv = bytes(range(16)); plaintext = b"CBC payload that is not block aligned"
    ciphertext = engine.encryptAESCBC(key, plaintext, iv)
    assert len(ciphertext) % 16 == 0
    assert engine.decryptAESCBC(key, ciphertext, iv) == plaintext


def testRSAOAEPAndPKCS8():
    engine = ffl_gnutls.CryptoEngine()
    privateKey, publicKey = engine.generateRSAKeyPair(2048)
    plaintext = b"RSA OAEP payload"
    ciphertext = engine.encryptRSAOAEP(publicKey, plaintext)
    assert engine.decryptRSAOAEP(privateKey, ciphertext) == plaintext
    assert engine.deriveRSAPublicKey(privateKey).pem == publicKey.pem
    pkcs8PEM = engine.serializeRSAPrivateKeyPKCS8(privateKey)
    assert pkcs8PEM.startswith("-----BEGIN PRIVATE KEY-----")
    assert pkcs8PEM.endswith("-----END PRIVATE KEY-----\n")


def testAESGCMRejectsTampering():
    engine = ffl_gnutls.CryptoEngine()
    key = bytes(range(32))
    nonce = bytes(range(12))
    ciphertext = bytearray(engine.encryptAESGCM(key, b"authenticated", nonce))
    ciphertext[-1] ^= 1
    try:
        engine.decryptAESGCM(key, nonce, ciphertext)
    except ffl_gnutls.GnuTLSError:
        return
    raise AssertionError("tampered AES-GCM ciphertext was accepted")
