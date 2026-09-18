#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2025-2026 FastFileLink contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import _ffl_gnutls as native

from .keys import RSAPrivateKey, RSAPublicKey


class CryptoEngine:
    """Focused OO facade over the native GnuTLS operations."""

    @staticmethod
    def _requireBytes(value, name):
        if isinstance(value, bytes):
            return value
            
        if isinstance(value, (bytearray, memoryview)):
            return bytes(value)
            
        raise TypeError(f"{name} must be bytes-like")

    @staticmethod
    def _requirePEMBytes(value, name):
        if isinstance(value, str):
            return value.encode("utf-8")
            
        return CryptoEngine._requireBytes(value, name)

    @classmethod
    def _coerceRSAPublicKey(cls, key):
        if isinstance(key, RSAPublicKey):
            return key

        if isinstance(key, RSAPrivateKey):
            publicPEM = native.deriveRSAPublicKeyPEM(
                key.pem.encode("ascii")
            )
            return RSAPublicKey(publicPEM.decode("ascii"))

        pemBytes = cls._requirePEMBytes(key, "key")
        normalizedPEM = native.normalizeRSAPublicKeyPEM(pemBytes)
        return RSAPublicKey(normalizedPEM.decode("ascii"))

    @classmethod
    def _coerceRSAPrivateKey(cls, key):
        if isinstance(key, RSAPrivateKey):
            return key

        pemBytes = cls._requirePEMBytes(key, "key")
        normalizedPEM = native.normalizeRSAPrivateKeyPEM(pemBytes)
        return RSAPrivateKey(normalizedPEM.decode("ascii"))

    @property
    def version(self):
        return native.version()

    def randomBytes(self, length):
        if not isinstance(length, int) or length <= 0:
            raise ValueError("length must be a positive integer")
            
        return native.randomBytes(length)

    def generateP384KeyPair(self):
        return native.generateP384KeyPair()

    def deriveP384PublicKey(self, privateKeyDER):
        privateKeyBytes = self._requireBytes(
            privateKeyDER,
            "privateKeyDER",
        )
        return native.deriveP384PublicKey(privateKeyBytes)

    def signSHA256(self, message, privateKeyDER):
        messageBytes = self._requireBytes(message, "message")
        privateKeyBytes = self._requireBytes(
            privateKeyDER,
            "privateKeyDER",
        )
        return native.signSHA256(messageBytes, privateKeyBytes)

    def verifySHA256(self, message, signature, publicKeyDER):
        messageBytes = self._requireBytes(message, "message")
        signatureBytes = self._requireBytes(signature, "signature")
        publicKeyBytes = self._requireBytes(
            publicKeyDER,
            "publicKeyDER",
        )
        return native.verifySHA256(
            messageBytes,
            signatureBytes,
            publicKeyBytes,
        )

    def deriveP384SharedSecret(self, privateKeyDER, peerPublicKeyDER):
        privateKeyBytes = self._requireBytes(
            privateKeyDER,
            "privateKeyDER",
        )
        publicKeyBytes = self._requireBytes(
            peerPublicKeyDER,
            "peerPublicKeyDER",
        )
        return native.deriveP384SharedSecret(
            privateKeyBytes,
            publicKeyBytes,
        )

    def deriveHKDFSHA256(
        self,
        keyMaterial,
        length=32,
        info=b"",
        salt=None,
    ):
        keyMaterialBytes = self._requireBytes(keyMaterial, "keyMaterial")
        infoBytes = self._requireBytes(info, "info")
        saltBytes = (
            None
            if salt is None
            else self._requireBytes(salt, "salt")
        )
        return native.deriveHKDFSHA256(
            keyMaterialBytes,
            length,
            infoBytes,
            saltBytes,
        )

    def encryptAESGCM(self, key, plaintext, nonce, aad=b""):
        return native.encryptAESGCM(
            self._requireBytes(key, "key"),
            self._requireBytes(plaintext, "plaintext"),
            self._requireBytes(nonce, "nonce"),
            self._requireBytes(aad, "aad"),
        )

    def decryptAESGCM(
        self,
        key,
        nonce,
        ciphertextWithTag,
        aad=b"",
    ):
        return native.decryptAESGCM(
            self._requireBytes(key, "key"),
            self._requireBytes(ciphertextWithTag, "ciphertextWithTag"),
            self._requireBytes(nonce, "nonce"),
            self._requireBytes(aad, "aad"),
        )

    def encryptAESCBC(self, key, plaintext, iv):
        return native.encryptAESCBC(
            self._requireBytes(key, "key"),
            self._requireBytes(plaintext, "plaintext"),
            self._requireBytes(iv, "iv"),
        )

    def decryptAESCBC(self, key, ciphertext, iv):
        return native.decryptAESCBC(
            self._requireBytes(key, "key"),
            self._requireBytes(ciphertext, "ciphertext"),
            self._requireBytes(iv, "iv"),
        )

    def loadRSAPublicKey(self, pem):
        return self._coerceRSAPublicKey(pem)

    def loadRSAPrivateKey(self, pem):
        return self._coerceRSAPrivateKey(pem)

    def generateRSAKeyPair(self, keySize=2048):
        privatePEM, publicPEM = native.generateRSAKeyPair(keySize)
        return (
            RSAPrivateKey(privatePEM.decode("ascii")),
            RSAPublicKey(publicPEM.decode("ascii")),
        )

    def deriveRSAPublicKey(self, privateKey):
        privateKeyObject = self._coerceRSAPrivateKey(privateKey)
        publicPEM = native.deriveRSAPublicKeyPEM(
            privateKeyObject.pem.encode("ascii")
        )
        return RSAPublicKey(publicPEM.decode("ascii"))

    def serializeRSAPublicKey(self, publicKey):
        return self._coerceRSAPublicKey(publicKey).pem

    def encryptRSAOAEP(self, publicKey, plaintext):
        publicKeyObject = self._coerceRSAPublicKey(publicKey)
        plaintextBytes = self._requireBytes(plaintext, "plaintext")
        return native.encryptRSAOAEPSHA256(
            publicKeyObject.pem.encode("ascii"),
            plaintextBytes,
        )

    def decryptRSAOAEP(self, privateKey, ciphertext):
        privateKeyObject = self._coerceRSAPrivateKey(privateKey)
        ciphertextBytes = self._requireBytes(ciphertext, "ciphertext")
        return native.decryptRSAOAEPSHA256(
            privateKeyObject.pem.encode("ascii"),
            ciphertextBytes,
        )

    def serializeRSAPrivateKeyPKCS8(self, privateKey):
        privateKeyObject = self._coerceRSAPrivateKey(privateKey)
        serializedPEM = native.serializeRSAPrivateKeyPKCS8(
            privateKeyObject.pem.encode("ascii")
        )
        return serializedPEM.decode("ascii")
