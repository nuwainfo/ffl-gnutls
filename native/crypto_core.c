/**
SPDX-License-Identifier: Apache-2.0

FastFileLink CLI - Fast, no-fuss file sharing
Copyright (C) 2025-2026 FastFileLink contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "crypto_core.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define FFL_GNUTLS_MIN_VERSION "3.8.4"
#define FFL_GNUTLS_P384_BITS 384
#define FFL_GNUTLS_P384_BYTES 48
#define FFL_GNUTLS_GCM_TAG_SIZE 16
#define FFL_GNUTLS_AES_BLOCK_SIZE 16

static void fflGnuTLSInitializeBuffer(FFLGnuTLSBuffer *buffer) {
    buffer->data = NULL;
    buffer->size = 0;
}

static void fflGnuTLSInitializeKeyPair(FFLGnuTLSKeyPair *keyPair) {
    fflGnuTLSInitializeBuffer(&keyPair->privateKey);
    fflGnuTLSInitializeBuffer(&keyPair->publicKey);
}

static int fflGnuTLSAllocateBuffer(size_t size, FFLGnuTLSBuffer *output) {
    size_t allocationSize;

    if (output == NULL) {
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    }
    
    fflGnuTLSInitializeBuffer(output);
    allocationSize = size == 0 ? 1 : size;
    output->data = malloc(allocationSize);
    
    if (output->data == NULL) {
        return FFL_GNUTLS_ERROR_ALLOCATION_FAILED;
    }
    
    output->size = size;
    return 0;
}

static int fflGnuTLSCopyBuffer(const unsigned char *data, size_t size, FFLGnuTLSBuffer *output) {
    int result;

    result = fflGnuTLSAllocateBuffer(size, output);
    if (result != 0) {
        return result;
    }
    
    if (size > 0) {
        memcpy(output->data, data, size);
    }
    
    return 0;
}

static int fflGnuTLSCopyDatum(const gnutls_datum_t *datum, FFLGnuTLSBuffer *output) {
    int result;

    result = fflGnuTLSCopyBuffer(datum->data, datum->size, output);
    if (datum->data != NULL) {
        gnutls_memset(datum->data, 0, datum->size);
        gnutls_free(datum->data);
    }
    
    return result;
}

static gnutls_x509_crt_fmt_t fflGnuTLSDetectFormat(const unsigned char *data, size_t size) {
    if (size >= 10 && memcmp(data, "-----BEGIN", 10) == 0) {
        return GNUTLS_X509_FMT_PEM;
    }
    return GNUTLS_X509_FMT_DER;
}

static int fflGnuTLSImportPrivateKey(const unsigned char *data, size_t size, gnutls_privkey_t *key) {
    gnutls_datum_t datum;
    int result;

    if (data == NULL || size == 0 || key == NULL) {
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    }
    
    result = gnutls_privkey_init(key);
    if (result < 0) {
        return result;
    }
    
    datum.data = (unsigned char *)data;
    datum.size = (unsigned int)size;
    result = gnutls_privkey_import_x509_raw(*key, &datum, fflGnuTLSDetectFormat(data, size), NULL, 0);
    if (result < 0) {
        gnutls_privkey_deinit(*key);
        *key = NULL;
    }
    
    return result;
}

static int fflGnuTLSImportPublicKey(const unsigned char *data, size_t size, gnutls_pubkey_t *key) {
    gnutls_datum_t datum;
    int result;

    if (data == NULL || size == 0 || key == NULL) {
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    }
    
    result = gnutls_pubkey_init(key);
    if (result < 0) {
        return result;
    }
    
    datum.data = (unsigned char *)data;
    datum.size = (unsigned int)size;
    result = gnutls_pubkey_import(*key, &datum, fflGnuTLSDetectFormat(data, size));
    if (result < 0) {
        gnutls_pubkey_deinit(*key);
        *key = NULL;
    }
    
    return result;
}

static int fflGnuTLSRequireP384Private(gnutls_privkey_t key) {
    unsigned int bits;
    int algorithm;

    algorithm = gnutls_privkey_get_pk_algorithm(key, &bits);
    if (algorithm != GNUTLS_PK_ECDSA || bits != FFL_GNUTLS_P384_BITS) {
        return FFL_GNUTLS_ERROR_UNSUPPORTED_KEY;
    }
    
    return 0;
}

static int fflGnuTLSRequireP384Public(gnutls_pubkey_t key) {
    unsigned int bits;
    int algorithm;

    algorithm = gnutls_pubkey_get_pk_algorithm(key, &bits);
    if (algorithm != GNUTLS_PK_ECDSA || bits != FFL_GNUTLS_P384_BITS) {
        return FFL_GNUTLS_ERROR_UNSUPPORTED_KEY;
    }
    
    return 0;
}

static int fflGnuTLSRequireRSAPrivate(gnutls_privkey_t key) {
    unsigned int bits;
    int algorithm;

    algorithm = gnutls_privkey_get_pk_algorithm(key, &bits);
    if (algorithm != GNUTLS_PK_RSA && algorithm != GNUTLS_PK_RSA_OAEP) {
        return FFL_GNUTLS_ERROR_UNSUPPORTED_KEY;
    }
    
    return 0;
}

static int fflGnuTLSRequireRSAPublic(gnutls_pubkey_t key) {
    unsigned int bits;
    int algorithm;

    algorithm = gnutls_pubkey_get_pk_algorithm(key, &bits);
    if (algorithm != GNUTLS_PK_RSA && algorithm != GNUTLS_PK_RSA_OAEP) {
        return FFL_GNUTLS_ERROR_UNSUPPORTED_KEY;
    }
    
    return 0;
}

static int fflGnuTLSExportPrivatePKCS8(gnutls_privkey_t key, gnutls_x509_crt_fmt_t format, FFLGnuTLSBuffer *output) {
    gnutls_x509_privkey_t x509Key;
    gnutls_datum_t datum = {NULL, 0};
    int result;

    result = gnutls_privkey_export_x509(key, &x509Key);
    if (result < 0) {
        return result;
    }
    
    result = gnutls_x509_privkey_export2_pkcs8(x509Key, format, NULL, GNUTLS_PKCS_PLAIN, &datum);
    gnutls_x509_privkey_deinit(x509Key);
    if (result < 0) {
        return result;
    }
    
    return fflGnuTLSCopyDatum(&datum, output);
}

static int fflGnuTLSExportPrivateNativePEM(gnutls_privkey_t key, FFLGnuTLSBuffer *output) {
    gnutls_x509_privkey_t x509Key;
    gnutls_datum_t datum = {NULL, 0};
    int result;

    result = gnutls_privkey_export_x509(key, &x509Key);
    if (result < 0) {
        return result;
    }
    
    result = gnutls_x509_privkey_export2(x509Key, GNUTLS_X509_FMT_PEM, &datum);
    gnutls_x509_privkey_deinit(x509Key);
    if (result < 0) {
        return result;
    }
    
    return fflGnuTLSCopyDatum(&datum, output);
}

static int fflGnuTLSExportPublic(gnutls_pubkey_t key, gnutls_x509_crt_fmt_t format, FFLGnuTLSBuffer *output) {
    gnutls_datum_t datum = {NULL, 0};
    int result;

    result = gnutls_pubkey_export2(key, format, &datum);
    if (result < 0) {
        return result;
    }
    
    return fflGnuTLSCopyDatum(&datum, output);
}

static gnutls_cipher_algorithm_t fflGnuTLSGetAESGCMCipher(size_t keySize) {
    if (keySize == 16) return GNUTLS_CIPHER_AES_128_GCM;
    if (keySize == 24) return GNUTLS_CIPHER_AES_192_GCM;
    if (keySize == 32) return GNUTLS_CIPHER_AES_256_GCM;
    return GNUTLS_CIPHER_UNKNOWN;
}

static gnutls_cipher_algorithm_t fflGnuTLSGetAESCBCCipher(size_t keySize) {
    if (keySize == 16) return GNUTLS_CIPHER_AES_128_CBC;
    if (keySize == 24) return GNUTLS_CIPHER_AES_192_CBC;
    if (keySize == 32) return GNUTLS_CIPHER_AES_256_CBC;
    return GNUTLS_CIPHER_UNKNOWN;
}

static int fflGnuTLSApplyRSAOAEP(gnutls_privkey_t privateKey, gnutls_pubkey_t publicKey) {
    gnutls_x509_spki_t spki;
    int result;

    result = gnutls_x509_spki_init(&spki);
    if (result < 0) 
        return result;
    
    result = gnutls_x509_spki_set_rsa_oaep_params(spki, GNUTLS_DIG_SHA256, NULL);
    
    if (result >= 0 && privateKey != NULL) 
        result = gnutls_privkey_set_spki(privateKey, spki, 0);
    
    if (result >= 0 && publicKey != NULL) 
        result = gnutls_pubkey_set_spki(publicKey, spki, 0);
    
    gnutls_x509_spki_deinit(spki);
    return result;
}

int fflGnuTLSInitialize(void) {
    if (gnutls_check_version(FFL_GNUTLS_MIN_VERSION) == NULL) {
        return FFL_GNUTLS_ERROR_VERSION_TOO_OLD;
    }
    
    return gnutls_global_init();
}

void fflGnuTLSDeinitialize(void) {
    gnutls_global_deinit();
}

const char *fflGnuTLSVersion(void) {
    const char *version = gnutls_check_version(NULL);
    return version == NULL ? "unknown" : version;
}

void fflGnuTLSFormatError(int errorCode, char *buffer, size_t bufferSize) {
    const char *message = NULL;
    if (buffer == NULL || bufferSize == 0) 
        return;
    
    switch (errorCode) {
        case FFL_GNUTLS_ERROR_INVALID_ARGUMENT: message = "invalid argument"; break;
        case FFL_GNUTLS_ERROR_ALLOCATION_FAILED: message = "memory allocation failed"; break;
        case FFL_GNUTLS_ERROR_UNSUPPORTED_KEY: message = "unsupported key type or size"; break;
        case FFL_GNUTLS_ERROR_INVALID_KEY_SIZE: message = "invalid key size"; break;
        case FFL_GNUTLS_ERROR_INVALID_PADDING: message = "invalid PKCS#7 padding"; break;
        case FFL_GNUTLS_ERROR_VERSION_TOO_OLD: message = "GnuTLS 3.8.4 or newer is required"; break;
        default: break;
    }
    snprintf(buffer, bufferSize, "%s", message != NULL ? message : gnutls_strerror(errorCode));
}

void fflGnuTLSBufferFree(FFLGnuTLSBuffer *buffer) {
    if (buffer == NULL || buffer->data == NULL) 
        return;
    
    gnutls_memset(buffer->data, 0, buffer->size);
    free(buffer->data);
    
    fflGnuTLSInitializeBuffer(buffer);
}

void fflGnuTLSKeyPairFree(FFLGnuTLSKeyPair *keyPair) {
    if (keyPair == NULL) 
        return;
    
    fflGnuTLSBufferFree(&keyPair->privateKey);
    fflGnuTLSBufferFree(&keyPair->publicKey);
}

int fflGnuTLSRandomBytes(size_t length, FFLGnuTLSBuffer *output) {
    int result;
    if (output == NULL || length == 0) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    result = fflGnuTLSAllocateBuffer(length, output);
    
    if (result != 0) 
        return result;
    
    result = gnutls_rnd(GNUTLS_RND_RANDOM, output->data, length);
    
    if (result < 0) 
        fflGnuTLSBufferFree(output);
    
    return result;
}

int fflGnuTLSGenerateP384KeyPair(FFLGnuTLSKeyPair *output) {
    gnutls_privkey_t privateKey = NULL;
    gnutls_pubkey_t publicKey = NULL;
    int result;

    if (output == NULL) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeKeyPair(output);
    result = gnutls_privkey_init(&privateKey);
    
    if (result >= 0) 
        result = gnutls_privkey_generate(privateKey, GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP384R1), 0);
    
    if (result >= 0) 
        result = fflGnuTLSExportPrivatePKCS8(privateKey, GNUTLS_X509_FMT_DER, &output->privateKey);
    
    if (result >= 0) 
        result = gnutls_pubkey_init(&publicKey);
    
    if (result >= 0) 
        result = gnutls_pubkey_import_privkey(publicKey, privateKey, 0, 0);
    
    if (result >= 0) 
        result = fflGnuTLSExportPublic(publicKey, GNUTLS_X509_FMT_DER, &output->publicKey);
    
    if (publicKey != NULL) 
        gnutls_pubkey_deinit(publicKey);
    
    if (privateKey != NULL) 
        gnutls_privkey_deinit(privateKey);
    
    if (result < 0) 
        fflGnuTLSKeyPairFree(output);
    
    return result;
}

int fflGnuTLSDeriveP384PublicKey(const unsigned char *privateKeyData, size_t privateKeySize, FFLGnuTLSBuffer *output) {
    gnutls_privkey_t privateKey = NULL;
    gnutls_pubkey_t publicKey = NULL;
    int result;

    if (output == NULL) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    result = fflGnuTLSImportPrivateKey(privateKeyData, privateKeySize, &privateKey);
    
    if (result >= 0) 
        result = fflGnuTLSRequireP384Private(privateKey);
    
    if (result >= 0) 
        result = gnutls_pubkey_init(&publicKey);
    
    if (result >= 0) 
        result = gnutls_pubkey_import_privkey(publicKey, privateKey, 0, 0);
    
    if (result >= 0) 
        result = fflGnuTLSExportPublic(publicKey, GNUTLS_X509_FMT_DER, output);
    
    if (publicKey != NULL) 
        gnutls_pubkey_deinit(publicKey);
    
    if (privateKey != NULL) 
        nutls_privkey_deinit(privateKey);
    
    return result;
}

int fflGnuTLSSignSHA256(const unsigned char *message, size_t messageSize, const unsigned char *privateKeyData, size_t privateKeySize, FFLGnuTLSBuffer *signature) {
    gnutls_privkey_t privateKey = NULL;
    gnutls_datum_t messageDatum;
    gnutls_datum_t signatureDatum = {NULL, 0};
    int result;

    if (signature == NULL || (message == NULL && messageSize != 0)) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(signature);
    
    result = fflGnuTLSImportPrivateKey(privateKeyData, privateKeySize, &privateKey);    
    if (result >= 0) 
        result = fflGnuTLSRequireP384Private(privateKey);
    
    messageDatum.data = (unsigned char *)message;
    messageDatum.size = (unsigned int)messageSize;
    
    if (result >= 0) 
        result = gnutls_privkey_sign_data2(privateKey, GNUTLS_SIGN_ECDSA_SHA256, 0, &messageDatum, &signatureDatum);
    
    if (result >= 0) 
        result = fflGnuTLSCopyDatum(&signatureDatum, signature);
    
    if (privateKey != NULL) 
        gnutls_privkey_deinit(privateKey);
    
    return result;
}

int fflGnuTLSVerifySHA256(const unsigned char *message, size_t messageSize, const unsigned char *signature, size_t signatureSize, const unsigned char *publicKeyData, size_t publicKeySize, int *isValid) {
    gnutls_pubkey_t publicKey = NULL;
    gnutls_datum_t messageDatum;
    gnutls_datum_t signatureDatum;
    int result;

    if (isValid == NULL) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    *isValid = 0;
    result = fflGnuTLSImportPublicKey(publicKeyData, publicKeySize, &publicKey);
    if (result >= 0) 
        result = fflGnuTLSRequireP384Public(publicKey);
    
    messageDatum.data = (unsigned char *)message;
    messageDatum.size = (unsigned int)messageSize;
    signatureDatum.data = (unsigned char *)signature;
    signatureDatum.size = (unsigned int)signatureSize;
    
    if (result >= 0) 
        result = gnutls_pubkey_verify_data2(publicKey, GNUTLS_SIGN_ECDSA_SHA256, 0, &messageDatum, &signatureDatum);
    
    if (result == GNUTLS_E_PK_SIG_VERIFY_FAILED) {
        result = 0;
    } else if (result >= 0) {
        *isValid = 1;
        result = 0;
    }
    
    if (publicKey != NULL) 
        gnutls_pubkey_deinit(publicKey);
    
    return result;
}

int fflGnuTLSDeriveP384SharedSecret(const unsigned char *privateKeyData, size_t privateKeySize, const unsigned char *peerPublicKeyData, size_t peerPublicKeySize, FFLGnuTLSBuffer *sharedSecret) {
    gnutls_privkey_t privateKey = NULL;
    gnutls_pubkey_t publicKey = NULL;
    gnutls_datum_t secret = {NULL, 0};
    int result;

    if (sharedSecret == NULL) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(sharedSecret);
    result = fflGnuTLSImportPrivateKey(privateKeyData, privateKeySize, &privateKey);
    
    if (result >= 0) 
        result = fflGnuTLSImportPublicKey(peerPublicKeyData, peerPublicKeySize, &publicKey);
    
    if (result >= 0) 
        result = fflGnuTLSRequireP384Private(privateKey);
    
    if (result >= 0) 
        result = fflGnuTLSRequireP384Public(publicKey);
    
    if (result >= 0) 
        result = gnutls_privkey_derive_secret(privateKey, publicKey, NULL, &secret, 0);
    
    if (result >= 0 && secret.size != FFL_GNUTLS_P384_BYTES) 
        result = FFL_GNUTLS_ERROR_INVALID_KEY_SIZE;
    
    if (result >= 0) 
        result = fflGnuTLSCopyDatum(&secret, sharedSecret);    
    else if (secret.data != NULL) 
        gnutls_free(secret.data);
    
    if (publicKey != NULL) 
        gnutls_pubkey_deinit(publicKey);
    
    if (privateKey != NULL) 
        gnutls_privkey_deinit(privateKey);
    
    return result;
}

int fflGnuTLSDeriveHKDFSHA256(const unsigned char *keyMaterial, size_t keyMaterialSize, size_t outputSize, const unsigned char *info, size_t infoSize, const unsigned char *salt, size_t saltSize, FFLGnuTLSBuffer *output) {
    unsigned char pseudoRandomKey[32];
    gnutls_datum_t keyDatum, saltDatum, pseudoDatum, infoDatum;
    int result;

    if (output == NULL || keyMaterial == NULL || keyMaterialSize == 0 || outputSize == 0) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    
    keyDatum.data = (unsigned char *)keyMaterial;
    keyDatum.size = (unsigned int)keyMaterialSize;
    saltDatum.data = (unsigned char *)salt;
    saltDatum.size = (unsigned int)saltSize;
    infoDatum.data = (unsigned char *)info;
    infoDatum.size = (unsigned int)infoSize;
    
    result = gnutls_hkdf_extract(GNUTLS_MAC_SHA256, &keyDatum, &saltDatum, pseudoRandomKey);
    if (result < 0) 
        return result;
    
    result = fflGnuTLSAllocateBuffer(outputSize, output);
    if (result != 0) { 
        gnutls_memset(pseudoRandomKey, 0, sizeof(pseudoRandomKey));
        return result; 
    }
    
    pseudoDatum.data = pseudoRandomKey;
    pseudoDatum.size = sizeof(pseudoRandomKey);
    result = gnutls_hkdf_expand(GNUTLS_MAC_SHA256, &pseudoDatum, &infoDatum, output->data, outputSize);
    gnutls_memset(pseudoRandomKey, 0, sizeof(pseudoRandomKey));
    
    if (result < 0) 
        fflGnuTLSBufferFree(output);
    
    return result;
}

int fflGnuTLSEncryptAESGCM(const unsigned char *key, size_t keySize, const unsigned char *plaintext, size_t plaintextSize, const unsigned char *nonce, size_t nonceSize, const unsigned char *aad, size_t aadSize, FFLGnuTLSBuffer *output) {
    gnutls_aead_cipher_hd_t handle;
    gnutls_datum_t keyDatum;
    gnutls_cipher_algorithm_t cipher;
    size_t outputSize;
    int result;

    if (output == NULL || nonce == NULL || nonceSize == 0) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    cipher = fflGnuTLSGetAESGCMCipher(keySize);
    
    if (cipher == GNUTLS_CIPHER_UNKNOWN) 
        return FFL_GNUTLS_ERROR_INVALID_KEY_SIZE;
    
    keyDatum.data = (unsigned char *)key;
    keyDatum.size = (unsigned int)keySize;
    result = gnutls_aead_cipher_init(&handle, cipher, &keyDatum);
    
    if (result < 0) 
        return result;
    
    result = fflGnuTLSAllocateBuffer(plaintextSize + FFL_GNUTLS_GCM_TAG_SIZE, output);
    if (result != 0) { 
        gnutls_aead_cipher_deinit(handle);
        return result;
    }
    
    outputSize = output->size;
    result = gnutls_aead_cipher_encrypt(handle, nonce, nonceSize, aad, aadSize, FFL_GNUTLS_GCM_TAG_SIZE, plaintext, plaintextSize, output->data, &outputSize);
    gnutls_aead_cipher_deinit(handle);
    
    if (result < 0) { 
        fflGnuTLSBufferFree(output);
        return result;
    }
    
    output->size = outputSize;
    return 0;
}

int fflGnuTLSDecryptAESGCM(const unsigned char *key, size_t keySize, const unsigned char *ciphertextWithTag, size_t ciphertextWithTagSize, const unsigned char *nonce, size_t nonceSize, const unsigned char *aad, size_t aadSize, FFLGnuTLSBuffer *output) {
    gnutls_aead_cipher_hd_t handle;
    gnutls_datum_t keyDatum;
    gnutls_cipher_algorithm_t cipher;
    size_t outputSize;
    int result;

    if (output == NULL || nonce == NULL || nonceSize == 0 || ciphertextWithTagSize < FFL_GNUTLS_GCM_TAG_SIZE) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    cipher = fflGnuTLSGetAESGCMCipher(keySize);
    
    if (cipher == GNUTLS_CIPHER_UNKNOWN) 
        return FFL_GNUTLS_ERROR_INVALID_KEY_SIZE;
    
    keyDatum.data = (unsigned char *)key;
    keyDatum.size = (unsigned int)keySize;
    result = gnutls_aead_cipher_init(&handle, cipher, &keyDatum);
    
    if (result < 0) 
        return result;
    
    result = fflGnuTLSAllocateBuffer(ciphertextWithTagSize - FFL_GNUTLS_GCM_TAG_SIZE, output);
    if (result != 0) { 
        gnutls_aead_cipher_deinit(handle);
        return result;
    }
    
    outputSize = output->size;
    result = gnutls_aead_cipher_decrypt(handle, nonce, nonceSize, aad, aadSize, FFL_GNUTLS_GCM_TAG_SIZE, ciphertextWithTag, ciphertextWithTagSize, output->data, &outputSize);
    gnutls_aead_cipher_deinit(handle);
    
    if (result < 0) { 
        fflGnuTLSBufferFree(output);
        return result;
    }
    
    output->size = outputSize;
    return 0;
}

int fflGnuTLSEncryptAESCBC(const unsigned char *key, size_t keySize, const unsigned char *plaintext, size_t plaintextSize, const unsigned char *iv, size_t ivSize, FFLGnuTLSBuffer *output) {
    gnutls_cipher_hd_t handle;
    gnutls_datum_t keyDatum, ivDatum;
    gnutls_cipher_algorithm_t cipher;
    unsigned char *padded = NULL;
    size_t padding, paddedSize;
    int result;

    if (output == NULL || iv == NULL || ivSize != FFL_GNUTLS_AES_BLOCK_SIZE) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    cipher = fflGnuTLSGetAESCBCCipher(keySize);
    
    if (cipher == GNUTLS_CIPHER_UNKNOWN) 
        return FFL_GNUTLS_ERROR_INVALID_KEY_SIZE;
    
    padding = FFL_GNUTLS_AES_BLOCK_SIZE - (plaintextSize % FFL_GNUTLS_AES_BLOCK_SIZE);
    paddedSize = plaintextSize + padding;
    padded = malloc(paddedSize);
    
    if (padded == NULL) 
        return FFL_GNUTLS_ERROR_ALLOCATION_FAILED;
    
    if (plaintextSize > 0) 
        memcpy(padded, plaintext, plaintextSize);
    
    memset(padded + plaintextSize, (int)padding, padding);
    keyDatum.data = (unsigned char *)key;
    keyDatum.size = (unsigned int)keySize;
    ivDatum.data = (unsigned char *)iv;
    ivDatum.size = (unsigned int)ivSize;
    result = gnutls_cipher_init(&handle, cipher, &keyDatum, &ivDatum);
    
    if (result < 0) {
        gnutls_memset(padded, 0, paddedSize);
        free(padded);
        return result;
    }

    result = fflGnuTLSAllocateBuffer(paddedSize, output);
    if (result == 0) {
        result = gnutls_cipher_encrypt2(
            handle,
            padded,
            paddedSize,
            output->data,
            output->size
        );
    }
    
    gnutls_cipher_deinit(handle);
    gnutls_memset(padded, 0, paddedSize);
    free(padded);

    if (result < 0) {
        fflGnuTLSBufferFree(output);
    }
    
    return result;
}

int fflGnuTLSDecryptAESCBC(const unsigned char *key, size_t keySize, const unsigned char *ciphertext, size_t ciphertextSize, const unsigned char *iv, size_t ivSize, FFLGnuTLSBuffer *output) {
    gnutls_cipher_hd_t handle;
    gnutls_datum_t keyDatum, ivDatum;
    gnutls_cipher_algorithm_t cipher;
    unsigned char padding;
    size_t index, plaintextSize;
    int result;

    if (output == NULL || iv == NULL || ivSize != FFL_GNUTLS_AES_BLOCK_SIZE || ciphertextSize == 0 || ciphertextSize % FFL_GNUTLS_AES_BLOCK_SIZE != 0) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    cipher = fflGnuTLSGetAESCBCCipher(keySize);
    
    if (cipher == GNUTLS_CIPHER_UNKNOWN) 
        return FFL_GNUTLS_ERROR_INVALID_KEY_SIZE;
    
    keyDatum.data = (unsigned char *)key;
    keyDatum.size = (unsigned int)keySize;
    ivDatum.data = (unsigned char *)iv;
    ivDatum.size = (unsigned int)ivSize;
    result = gnutls_cipher_init(&handle, cipher, &keyDatum, &ivDatum);
    
    if (result < 0) {
        return result;
    }

    result = fflGnuTLSAllocateBuffer(ciphertextSize, output);
    if (result == 0) {
        result = gnutls_cipher_decrypt2(
            handle,
            ciphertext,
            ciphertextSize,
            output->data,
            output->size
        );
    }
    
    gnutls_cipher_deinit(handle);

    if (result < 0) {
        fflGnuTLSBufferFree(output);
        return result;
    }
    
    padding = output->data[ciphertextSize - 1];
    if (padding == 0 || padding > FFL_GNUTLS_AES_BLOCK_SIZE || padding > ciphertextSize) { 
        fflGnuTLSBufferFree(output);
        return FFL_GNUTLS_ERROR_INVALID_PADDING;
    }
    
    for (index = 0; index < padding; index++) {
        if (output->data[ciphertextSize - 1 - index] != padding) { 
            fflGnuTLSBufferFree(output);
            return FFL_GNUTLS_ERROR_INVALID_PADDING;
    }
    }
    
    plaintextSize = ciphertextSize - padding;
    output->size = plaintextSize;
    return 0;
}

int fflGnuTLSGenerateRSAKeyPair(unsigned int keySize, FFLGnuTLSKeyPair *output) {
    gnutls_privkey_t privateKey = NULL;
    gnutls_pubkey_t publicKey = NULL;
    int result;

    if (output == NULL || keySize < 2048 || keySize > 8192 || keySize % 256 != 0) 
        return FFL_GNUTLS_ERROR_INVALID_KEY_SIZE;
    
    fflGnuTLSInitializeKeyPair(output);
    result = gnutls_privkey_init(&privateKey);
    
    if (result >= 0) 
        result = gnutls_privkey_generate(privateKey, GNUTLS_PK_RSA, keySize, 0);
    
    if (result >= 0) 
        result = fflGnuTLSExportPrivateNativePEM(privateKey, &output->privateKey);
    
    if (result >= 0) 
        result = gnutls_pubkey_init(&publicKey);
    
    if (result >= 0) 
        result = gnutls_pubkey_import_privkey(publicKey, privateKey, 0, 0);
    
    if (result >= 0) 
        result = fflGnuTLSExportPublic(publicKey, GNUTLS_X509_FMT_PEM, &output->publicKey);
    
    if (publicKey != NULL) 
        gnutls_pubkey_deinit(publicKey);
    
    if (privateKey != NULL) 
        gnutls_privkey_deinit(privateKey);
    
    if (result < 0) 
        fflGnuTLSKeyPairFree(output);
    
    return result;
}

int fflGnuTLSNormalizeRSAPublicKeyPEM(const unsigned char *data, size_t size, FFLGnuTLSBuffer *output) {
    gnutls_pubkey_t key = NULL;
    int result;
    
    if (output == NULL) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    result = fflGnuTLSImportPublicKey(data, size, &key);
    
    if (result >= 0) 
        result = fflGnuTLSRequireRSAPublic(key);
    
    if (result >= 0) 
        result = fflGnuTLSExportPublic(key, GNUTLS_X509_FMT_PEM, output);
    
    if (key != NULL) 
        gnutls_pubkey_deinit(key);
    
    return result;
}

int fflGnuTLSNormalizeRSAPrivateKeyPEM(const unsigned char *data, size_t size, FFLGnuTLSBuffer *output) {
    gnutls_privkey_t key = NULL;
    int result;
    
    if (output == NULL) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    result = fflGnuTLSImportPrivateKey(data, size, &key);
    
    if (result >= 0) 
        result = fflGnuTLSRequireRSAPrivate(key);
    
    if (result >= 0) 
        result = fflGnuTLSExportPrivateNativePEM(key, output);
    
    if (key != NULL) 
        gnutls_privkey_deinit(key);
    
    return result;
}

int fflGnuTLSDeriveRSAPublicKeyPEM(const unsigned char *data, size_t size, FFLGnuTLSBuffer *output) {
    gnutls_privkey_t privateKey = NULL;
    gnutls_pubkey_t publicKey = NULL;
    int result;
    
    if (output == NULL) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    result = fflGnuTLSImportPrivateKey(data, size, &privateKey);
    
    if (result >= 0) 
        result = fflGnuTLSRequireRSAPrivate(privateKey);
    
    if (result >= 0) 
        result = gnutls_pubkey_init(&publicKey);
    
    if (result >= 0) 
        result = gnutls_pubkey_import_privkey(publicKey, privateKey, 0, 0);
    
    if (result >= 0) 
        result = fflGnuTLSExportPublic(publicKey, GNUTLS_X509_FMT_PEM, output);
    
    if (publicKey != NULL) 
        gnutls_pubkey_deinit(publicKey);
    
    if (privateKey != NULL) 
        gnutls_privkey_deinit(privateKey);
    
    return result;
}

int fflGnuTLSEncryptRSAOAEPSHA256(const unsigned char *data, size_t size, const unsigned char *plaintext, size_t plaintextSize, FFLGnuTLSBuffer *output) {
    gnutls_pubkey_t key = NULL;
    gnutls_datum_t plaintextDatum, ciphertext = {NULL, 0};
    int result;
    
    if (output == NULL) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    result = fflGnuTLSImportPublicKey(data, size, &key);
    
    if (result >= 0) 
        result = fflGnuTLSRequireRSAPublic(key);
    
    if (result >= 0) 
        result = fflGnuTLSApplyRSAOAEP(NULL, key);
    
    plaintextDatum.data = (unsigned char *)plaintext;
    plaintextDatum.size = (unsigned int)plaintextSize;
    
    if (result >= 0) 
        result = gnutls_pubkey_encrypt_data(key, 0, &plaintextDatum, &ciphertext);
    
    if (result >= 0) 
        result = fflGnuTLSCopyDatum(&ciphertext, output);
    
    if (key != NULL) 
        gnutls_pubkey_deinit(key);
    
    return result;
}

int fflGnuTLSDecryptRSAOAEPSHA256(const unsigned char *data, size_t size, const unsigned char *ciphertextData, size_t ciphertextSize, FFLGnuTLSBuffer *output) {
    gnutls_privkey_t key = NULL;
    gnutls_datum_t ciphertextDatum, plaintext = {NULL, 0};
    int result;
    
    if (output == NULL) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    result = fflGnuTLSImportPrivateKey(data, size, &key);
    
    if (result >= 0) 
        result = fflGnuTLSRequireRSAPrivate(key);
    
    if (result >= 0) 
        result = fflGnuTLSApplyRSAOAEP(key, NULL);
    
    ciphertextDatum.data = (unsigned char *)ciphertextData;
    ciphertextDatum.size = (unsigned int)ciphertextSize;
    
    if (result >= 0) 
        result = gnutls_privkey_decrypt_data(key, 0, &ciphertextDatum, &plaintext);
    
    if (result >= 0) 
        result = fflGnuTLSCopyDatum(&plaintext, output);
    
    if (key != NULL) 
        gnutls_privkey_deinit(key);
    
    return result;
}

int fflGnuTLSSerializeRSAPrivateKeyPKCS8(const unsigned char *data, size_t size, FFLGnuTLSBuffer *output) {
    gnutls_privkey_t key = NULL;
    int result;
    
    if (output == NULL) 
        return FFL_GNUTLS_ERROR_INVALID_ARGUMENT;
    
    fflGnuTLSInitializeBuffer(output);
    result = fflGnuTLSImportPrivateKey(data, size, &key);
    
    if (result >= 0) 
        result = fflGnuTLSRequireRSAPrivate(key);
    
    if (result >= 0) 
        result = fflGnuTLSExportPrivatePKCS8(key, GNUTLS_X509_FMT_PEM, output);
    
    if (key != NULL) 
        gnutls_privkey_deinit(key);
    
    return result;
}
