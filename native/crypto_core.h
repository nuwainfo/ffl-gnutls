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

#ifndef FFL_GNUTLS_CRYPTO_CORE_H
#define FFL_GNUTLS_CRYPTO_CORE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FFLGnuTLSBuffer {
    unsigned char *data;
    size_t size;
} FFLGnuTLSBuffer;

typedef struct FFLGnuTLSKeyPair {
    FFLGnuTLSBuffer privateKey;
    FFLGnuTLSBuffer publicKey;
} FFLGnuTLSKeyPair;

enum {
    FFL_GNUTLS_ERROR_INVALID_ARGUMENT = -0x7F01,
    FFL_GNUTLS_ERROR_ALLOCATION_FAILED = -0x7F02,
    FFL_GNUTLS_ERROR_UNSUPPORTED_KEY = -0x7F03,
    FFL_GNUTLS_ERROR_INVALID_KEY_SIZE = -0x7F04,
    FFL_GNUTLS_ERROR_INVALID_PADDING = -0x7F05,
    FFL_GNUTLS_ERROR_VERSION_TOO_OLD = -0x7F06
};

int fflGnuTLSInitialize(void);
void fflGnuTLSDeinitialize(void);
const char *fflGnuTLSVersion(void);
void fflGnuTLSFormatError(int errorCode, char *buffer, size_t bufferSize);

void fflGnuTLSBufferFree(FFLGnuTLSBuffer *buffer);
void fflGnuTLSKeyPairFree(FFLGnuTLSKeyPair *keyPair);

int fflGnuTLSRandomBytes(size_t length, FFLGnuTLSBuffer *output);
int fflGnuTLSGenerateP384KeyPair(FFLGnuTLSKeyPair *output);
int fflGnuTLSDeriveP384PublicKey(const unsigned char *privateKey, size_t privateKeySize, FFLGnuTLSBuffer *output);
int fflGnuTLSSignSHA256(const unsigned char *message, size_t messageSize, const unsigned char *privateKey, size_t privateKeySize, FFLGnuTLSBuffer *signature);
int fflGnuTLSVerifySHA256(const unsigned char *message, size_t messageSize, const unsigned char *signature, size_t signatureSize, const unsigned char *publicKey, size_t publicKeySize, int *isValid);
int fflGnuTLSDeriveP384SharedSecret(const unsigned char *privateKey, size_t privateKeySize, const unsigned char *peerPublicKey, size_t peerPublicKeySize, FFLGnuTLSBuffer *sharedSecret);

int fflGnuTLSDeriveHKDFSHA256(const unsigned char *keyMaterial, size_t keyMaterialSize, size_t outputSize, const unsigned char *info, size_t infoSize, const unsigned char *salt, size_t saltSize, FFLGnuTLSBuffer *output);
int fflGnuTLSEncryptAESGCM(const unsigned char *key, size_t keySize, const unsigned char *plaintext, size_t plaintextSize, const unsigned char *nonce, size_t nonceSize, const unsigned char *aad, size_t aadSize, FFLGnuTLSBuffer *output);
int fflGnuTLSDecryptAESGCM(const unsigned char *key, size_t keySize, const unsigned char *ciphertextWithTag, size_t ciphertextWithTagSize, const unsigned char *nonce, size_t nonceSize, const unsigned char *aad, size_t aadSize, FFLGnuTLSBuffer *output);
int fflGnuTLSEncryptAESCBC(const unsigned char *key, size_t keySize, const unsigned char *plaintext, size_t plaintextSize, const unsigned char *iv, size_t ivSize, FFLGnuTLSBuffer *output);
int fflGnuTLSDecryptAESCBC(const unsigned char *key, size_t keySize, const unsigned char *ciphertext, size_t ciphertextSize, const unsigned char *iv, size_t ivSize, FFLGnuTLSBuffer *output);

int fflGnuTLSGenerateRSAKeyPair(unsigned int keySize, FFLGnuTLSKeyPair *output);
int fflGnuTLSNormalizeRSAPublicKeyPEM(const unsigned char *publicKeyPEM, size_t publicKeyPEMSize, FFLGnuTLSBuffer *output);
int fflGnuTLSNormalizeRSAPrivateKeyPEM(const unsigned char *privateKeyPEM, size_t privateKeyPEMSize, FFLGnuTLSBuffer *output);
int fflGnuTLSDeriveRSAPublicKeyPEM(const unsigned char *privateKeyPEM, size_t privateKeyPEMSize, FFLGnuTLSBuffer *output);
int fflGnuTLSEncryptRSAOAEPSHA256(const unsigned char *publicKeyPEM, size_t publicKeyPEMSize, const unsigned char *plaintext, size_t plaintextSize, FFLGnuTLSBuffer *output);
int fflGnuTLSDecryptRSAOAEPSHA256(const unsigned char *privateKeyPEM, size_t privateKeyPEMSize, const unsigned char *ciphertext, size_t ciphertextSize, FFLGnuTLSBuffer *output);
int fflGnuTLSSerializeRSAPrivateKeyPKCS8(const unsigned char *privateKeyPEM, size_t privateKeyPEMSize, FFLGnuTLSBuffer *output);

#ifdef __cplusplus
}
#endif

#endif
