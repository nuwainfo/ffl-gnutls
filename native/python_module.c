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

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "crypto_core.h"

typedef struct FFLGnuTLSModuleState {
    PyObject *errorType;
    int initialized;
} FFLGnuTLSModuleState;

typedef int (*FFLGnuTLSPEMFunction)(
    const unsigned char *,
    size_t,
    FFLGnuTLSBuffer *
);

static FFLGnuTLSModuleState *fflGetModuleState(PyObject *module) {
    return (FFLGnuTLSModuleState *)PyModule_GetState(module);
}

static PyObject *fflRaiseError(
    PyObject *module,
    const char *operation,
    int errorCode
) {
    FFLGnuTLSModuleState *state;
    char message[256];

    state = fflGetModuleState(module);
    fflGnuTLSFormatError(errorCode, message, sizeof(message));
    PyErr_Format(
        state->errorType,
        "%s failed: %s (%d)",
        operation,
        message,
        errorCode
    );
    return NULL;
}

static PyObject *fflBuildBytes(FFLGnuTLSBuffer *buffer) {
    PyObject *value;

    value = PyBytes_FromStringAndSize(
        (const char *)buffer->data,
        (Py_ssize_t)buffer->size
    );
    fflGnuTLSBufferFree(buffer);
    return value;
}

static int fflGetOptionalBuffer(
    PyObject *value,
    Py_buffer *buffer,
    const unsigned char **data,
    size_t *size
) {
    if (value == Py_None) {
        *data = NULL;
        *size = 0;
        return 0;
    }

    if (PyObject_GetBuffer(value, buffer, PyBUF_SIMPLE) != 0) {
        return -1;
    }

    *data = buffer->buf;
    *size = (size_t)buffer->len;
    return 1;
}

static void fflReleaseOptionalBuffer(Py_buffer *buffer, int acquired) {
    if (acquired > 0) {
        PyBuffer_Release(buffer);
    }
}

static PyObject *pyVersion(
    PyObject *module,
    PyObject *Py_UNUSED(args)
) {
    (void)module;
    return PyUnicode_FromString(fflGnuTLSVersion());
}

static PyObject *pyRandomBytes(PyObject *module, PyObject *args) {
    Py_ssize_t length;
    FFLGnuTLSBuffer output;
    int result;

    if (!PyArg_ParseTuple(args, "n:randomBytes", &length)) {
        return NULL;
    }
    if (length <= 0) {
        PyErr_SetString(PyExc_ValueError, "length must be positive");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = fflGnuTLSRandomBytes((size_t)length, &output);
    Py_END_ALLOW_THREADS

    if (result < 0) {
        return fflRaiseError(module, "randomBytes", result);
    }
    return fflBuildBytes(&output);
}

static PyObject *pyGenerateP384KeyPair(
    PyObject *module,
    PyObject *Py_UNUSED(args)
) {
    FFLGnuTLSKeyPair keyPair;
    PyObject *privateKey;
    PyObject *publicKey;
    PyObject *resultTuple;
    int result;

    Py_BEGIN_ALLOW_THREADS
    result = fflGnuTLSGenerateP384KeyPair(&keyPair);
    Py_END_ALLOW_THREADS

    if (result < 0) {
        return fflRaiseError(module, "generateP384KeyPair", result);
    }

    privateKey = fflBuildBytes(&keyPair.privateKey);
    if (privateKey == NULL) {
        fflGnuTLSBufferFree(&keyPair.publicKey);
        return NULL;
    }

    publicKey = fflBuildBytes(&keyPair.publicKey);
    if (publicKey == NULL) {
        Py_DECREF(privateKey);
        return NULL;
    }

    resultTuple = PyTuple_Pack(2, privateKey, publicKey);
    Py_DECREF(publicKey);
    Py_DECREF(privateKey);
    return resultTuple;
}

static PyObject *pyDeriveP384PublicKey(
    PyObject *module,
    PyObject *args
) {
    Py_buffer privateKey;
    FFLGnuTLSBuffer output;
    int result;

    if (!PyArg_ParseTuple(args, "y*:deriveP384PublicKey", &privateKey)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = fflGnuTLSDeriveP384PublicKey(
        privateKey.buf,
        (size_t)privateKey.len,
        &output
    );
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&privateKey);

    if (result < 0) {
        return fflRaiseError(module, "deriveP384PublicKey", result);
    }
    return fflBuildBytes(&output);
}

static PyObject *pySignSHA256(PyObject *module, PyObject *args) {
    Py_buffer message;
    Py_buffer privateKey;
    FFLGnuTLSBuffer output;
    int result;

    if (!PyArg_ParseTuple(
        args,
        "y*y*:signSHA256",
        &message,
        &privateKey
    )) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = fflGnuTLSSignSHA256(
        message.buf,
        (size_t)message.len,
        privateKey.buf,
        (size_t)privateKey.len,
        &output
    );
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&privateKey);
    PyBuffer_Release(&message);

    if (result < 0) {
        return fflRaiseError(module, "signSHA256", result);
    }
    return fflBuildBytes(&output);
}

static PyObject *pyVerifySHA256(PyObject *module, PyObject *args) {
    Py_buffer message;
    Py_buffer signature;
    Py_buffer publicKey;
    int isValid;
    int result;

    if (!PyArg_ParseTuple(
        args,
        "y*y*y*:verifySHA256",
        &message,
        &signature,
        &publicKey
    )) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = fflGnuTLSVerifySHA256(
        message.buf,
        (size_t)message.len,
        signature.buf,
        (size_t)signature.len,
        publicKey.buf,
        (size_t)publicKey.len,
        &isValid
    );
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&publicKey);
    PyBuffer_Release(&signature);
    PyBuffer_Release(&message);

    if (result < 0) {
        return fflRaiseError(module, "verifySHA256", result);
    }
    if (isValid) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyObject *pyDeriveP384SharedSecret(
    PyObject *module,
    PyObject *args
) {
    Py_buffer privateKey;
    Py_buffer publicKey;
    FFLGnuTLSBuffer output;
    int result;

    if (!PyArg_ParseTuple(
        args,
        "y*y*:deriveP384SharedSecret",
        &privateKey,
        &publicKey
    )) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = fflGnuTLSDeriveP384SharedSecret(
        privateKey.buf,
        (size_t)privateKey.len,
        publicKey.buf,
        (size_t)publicKey.len,
        &output
    );
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&publicKey);
    PyBuffer_Release(&privateKey);

    if (result < 0) {
        return fflRaiseError(
            module,
            "deriveP384SharedSecret",
            result
        );
    }
    return fflBuildBytes(&output);
}

static PyObject *pyDeriveHKDFSHA256(
    PyObject *module,
    PyObject *args
) {
    Py_buffer keyMaterial;
    Py_ssize_t length;
    PyObject *infoObject;
    PyObject *saltObject;
    Py_buffer infoBuffer = {0};
    Py_buffer saltBuffer = {0};
    const unsigned char *info;
    const unsigned char *salt;
    size_t infoSize;
    size_t saltSize;
    int infoAcquired;
    int saltAcquired;
    FFLGnuTLSBuffer output;
    int result;

    infoObject = Py_None;
    saltObject = Py_None;
    if (!PyArg_ParseTuple(
        args,
        "y*n|OO:deriveHKDFSHA256",
        &keyMaterial,
        &length,
        &infoObject,
        &saltObject
    )) {
        return NULL;
    }

    if (length <= 0) {
        PyBuffer_Release(&keyMaterial);
        PyErr_SetString(PyExc_ValueError, "length must be positive");
        return NULL;
    }

    infoAcquired = fflGetOptionalBuffer(
        infoObject,
        &infoBuffer,
        &info,
        &infoSize
    );
    if (infoAcquired < 0) {
        PyBuffer_Release(&keyMaterial);
        return NULL;
    }

    saltAcquired = fflGetOptionalBuffer(
        saltObject,
        &saltBuffer,
        &salt,
        &saltSize
    );
    if (saltAcquired < 0) {
        fflReleaseOptionalBuffer(&infoBuffer, infoAcquired);
        PyBuffer_Release(&keyMaterial);
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = fflGnuTLSDeriveHKDFSHA256(
        keyMaterial.buf,
        (size_t)keyMaterial.len,
        (size_t)length,
        info,
        infoSize,
        salt,
        saltSize,
        &output
    );
    Py_END_ALLOW_THREADS

    fflReleaseOptionalBuffer(&saltBuffer, saltAcquired);
    fflReleaseOptionalBuffer(&infoBuffer, infoAcquired);
    PyBuffer_Release(&keyMaterial);

    if (result < 0) {
        return fflRaiseError(module, "deriveHKDFSHA256", result);
    }
    return fflBuildBytes(&output);
}

static PyObject *fflRunAESGCM(
    PyObject *module,
    PyObject *args,
    int encrypt
) {
    Py_buffer key;
    Py_buffer data;
    Py_buffer nonce;
    PyObject *aadObject;
    Py_buffer aadBuffer = {0};
    const unsigned char *aad;
    size_t aadSize;
    int aadAcquired;
    FFLGnuTLSBuffer output;
    int result;

    aadObject = Py_None;
    if (!PyArg_ParseTuple(
        args,
        "y*y*y*|O",
        &key,
        &data,
        &nonce,
        &aadObject
    )) {
        return NULL;
    }

    aadAcquired = fflGetOptionalBuffer(
        aadObject,
        &aadBuffer,
        &aad,
        &aadSize
    );
    if (aadAcquired < 0) {
        PyBuffer_Release(&nonce);
        PyBuffer_Release(&data);
        PyBuffer_Release(&key);
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    if (encrypt) {
        result = fflGnuTLSEncryptAESGCM(
            key.buf,
            (size_t)key.len,
            data.buf,
            (size_t)data.len,
            nonce.buf,
            (size_t)nonce.len,
            aad,
            aadSize,
            &output
        );
    } else {
        result = fflGnuTLSDecryptAESGCM(
            key.buf,
            (size_t)key.len,
            data.buf,
            (size_t)data.len,
            nonce.buf,
            (size_t)nonce.len,
            aad,
            aadSize,
            &output
        );
    }
    Py_END_ALLOW_THREADS

    fflReleaseOptionalBuffer(&aadBuffer, aadAcquired);
    PyBuffer_Release(&nonce);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);

    if (result < 0) {
        return fflRaiseError(
            module,
            encrypt ? "encryptAESGCM" : "decryptAESGCM",
            result
        );
    }
    return fflBuildBytes(&output);
}

static PyObject *pyEncryptAESGCM(PyObject *module, PyObject *args) {
    return fflRunAESGCM(module, args, 1);
}

static PyObject *pyDecryptAESGCM(PyObject *module, PyObject *args) {
    return fflRunAESGCM(module, args, 0);
}

static PyObject *fflRunAESCBC(
    PyObject *module,
    PyObject *args,
    int encrypt
) {
    Py_buffer key;
    Py_buffer data;
    Py_buffer iv;
    FFLGnuTLSBuffer output;
    int result;

    if (!PyArg_ParseTuple(args, "y*y*y*", &key, &data, &iv)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    if (encrypt) {
        result = fflGnuTLSEncryptAESCBC(
            key.buf,
            (size_t)key.len,
            data.buf,
            (size_t)data.len,
            iv.buf,
            (size_t)iv.len,
            &output
        );
    } else {
        result = fflGnuTLSDecryptAESCBC(
            key.buf,
            (size_t)key.len,
            data.buf,
            (size_t)data.len,
            iv.buf,
            (size_t)iv.len,
            &output
        );
    }
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&iv);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);

    if (result < 0) {
        return fflRaiseError(
            module,
            encrypt ? "encryptAESCBC" : "decryptAESCBC",
            result
        );
    }
    return fflBuildBytes(&output);
}

static PyObject *pyEncryptAESCBC(PyObject *module, PyObject *args) {
    return fflRunAESCBC(module, args, 1);
}

static PyObject *pyDecryptAESCBC(PyObject *module, PyObject *args) {
    return fflRunAESCBC(module, args, 0);
}

static PyObject *pyGenerateRSAKeyPair(
    PyObject *module,
    PyObject *args
) {
    unsigned int keySize;
    FFLGnuTLSKeyPair keyPair;
    PyObject *privateKey;
    PyObject *publicKey;
    PyObject *resultTuple;
    int result;

    keySize = 2048;
    if (!PyArg_ParseTuple(args, "|I:generateRSAKeyPair", &keySize)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = fflGnuTLSGenerateRSAKeyPair(keySize, &keyPair);
    Py_END_ALLOW_THREADS

    if (result < 0) {
        return fflRaiseError(module, "generateRSAKeyPair", result);
    }

    privateKey = fflBuildBytes(&keyPair.privateKey);
    if (privateKey == NULL) {
        fflGnuTLSBufferFree(&keyPair.publicKey);
        return NULL;
    }

    publicKey = fflBuildBytes(&keyPair.publicKey);
    if (publicKey == NULL) {
        Py_DECREF(privateKey);
        return NULL;
    }

    resultTuple = PyTuple_Pack(2, privateKey, publicKey);
    Py_DECREF(publicKey);
    Py_DECREF(privateKey);
    return resultTuple;
}

static PyObject *fflRunPEMOperation(
    PyObject *module,
    PyObject *args,
    const char *operation,
    FFLGnuTLSPEMFunction function
) {
    Py_buffer key;
    FFLGnuTLSBuffer output;
    int result;

    if (!PyArg_ParseTuple(args, "y*", &key)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = function(key.buf, (size_t)key.len, &output);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&key);
    if (result < 0) {
        return fflRaiseError(module, operation, result);
    }
    return fflBuildBytes(&output);
}

static PyObject *pyNormalizeRSAPublicKeyPEM(
    PyObject *module,
    PyObject *args
) {
    return fflRunPEMOperation(
        module,
        args,
        "normalizeRSAPublicKeyPEM",
        fflGnuTLSNormalizeRSAPublicKeyPEM
    );
}

static PyObject *pyNormalizeRSAPrivateKeyPEM(
    PyObject *module,
    PyObject *args
) {
    return fflRunPEMOperation(
        module,
        args,
        "normalizeRSAPrivateKeyPEM",
        fflGnuTLSNormalizeRSAPrivateKeyPEM
    );
}

static PyObject *pyDeriveRSAPublicKeyPEM(
    PyObject *module,
    PyObject *args
) {
    return fflRunPEMOperation(
        module,
        args,
        "deriveRSAPublicKeyPEM",
        fflGnuTLSDeriveRSAPublicKeyPEM
    );
}

static PyObject *pySerializeRSAPrivateKeyPKCS8(
    PyObject *module,
    PyObject *args
) {
    return fflRunPEMOperation(
        module,
        args,
        "serializeRSAPrivateKeyPKCS8",
        fflGnuTLSSerializeRSAPrivateKeyPKCS8
    );
}

static PyObject *fflRunRSAOAEP(
    PyObject *module,
    PyObject *args,
    int encrypt
) {
    Py_buffer key;
    Py_buffer data;
    FFLGnuTLSBuffer output;
    int result;

    if (!PyArg_ParseTuple(args, "y*y*", &key, &data)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    if (encrypt) {
        result = fflGnuTLSEncryptRSAOAEPSHA256(
            key.buf,
            (size_t)key.len,
            data.buf,
            (size_t)data.len,
            &output
        );
    } else {
        result = fflGnuTLSDecryptRSAOAEPSHA256(
            key.buf,
            (size_t)key.len,
            data.buf,
            (size_t)data.len,
            &output
        );
    }
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);

    if (result < 0) {
        return fflRaiseError(
            module,
            encrypt ? "encryptRSAOAEPSHA256" : "decryptRSAOAEPSHA256",
            result
        );
    }
    return fflBuildBytes(&output);
}

static PyObject *pyEncryptRSAOAEPSHA256(
    PyObject *module,
    PyObject *args
) {
    return fflRunRSAOAEP(module, args, 1);
}

static PyObject *pyDecryptRSAOAEPSHA256(
    PyObject *module,
    PyObject *args
) {
    return fflRunRSAOAEP(module, args, 0);
}

static PyMethodDef moduleMethods[] = {
    {"version", pyVersion, METH_NOARGS, NULL},
    {"randomBytes", pyRandomBytes, METH_VARARGS, NULL},
    {"generateP384KeyPair", pyGenerateP384KeyPair, METH_NOARGS, NULL},
    {"deriveP384PublicKey", pyDeriveP384PublicKey, METH_VARARGS, NULL},
    {"signSHA256", pySignSHA256, METH_VARARGS, NULL},
    {"verifySHA256", pyVerifySHA256, METH_VARARGS, NULL},
    {"deriveP384SharedSecret", pyDeriveP384SharedSecret, METH_VARARGS, NULL},
    {"deriveHKDFSHA256", pyDeriveHKDFSHA256, METH_VARARGS, NULL},
    {"encryptAESGCM", pyEncryptAESGCM, METH_VARARGS, NULL},
    {"decryptAESGCM", pyDecryptAESGCM, METH_VARARGS, NULL},
    {"encryptAESCBC", pyEncryptAESCBC, METH_VARARGS, NULL},
    {"decryptAESCBC", pyDecryptAESCBC, METH_VARARGS, NULL},
    {"generateRSAKeyPair", pyGenerateRSAKeyPair, METH_VARARGS, NULL},
    {"normalizeRSAPublicKeyPEM", pyNormalizeRSAPublicKeyPEM, METH_VARARGS, NULL},
    {"normalizeRSAPrivateKeyPEM", pyNormalizeRSAPrivateKeyPEM, METH_VARARGS, NULL},
    {"deriveRSAPublicKeyPEM", pyDeriveRSAPublicKeyPEM, METH_VARARGS, NULL},
    {"encryptRSAOAEPSHA256", pyEncryptRSAOAEPSHA256, METH_VARARGS, NULL},
    {"decryptRSAOAEPSHA256", pyDecryptRSAOAEPSHA256, METH_VARARGS, NULL},
    {"serializeRSAPrivateKeyPKCS8", pySerializeRSAPrivateKeyPKCS8, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static int moduleTraverse(
    PyObject *module,
    visitproc visit,
    void *arg
) {
    FFLGnuTLSModuleState *state;

    state = fflGetModuleState(module);
    Py_VISIT(state->errorType);
    return 0;
}

static int moduleClear(PyObject *module) {
    FFLGnuTLSModuleState *state;

    state = fflGetModuleState(module);
    Py_CLEAR(state->errorType);
    return 0;
}

static void moduleFree(void *module) {
    FFLGnuTLSModuleState *state;

    state = fflGetModuleState((PyObject *)module);
    if (state != NULL && state->initialized) {
        fflGnuTLSDeinitialize();
        state->initialized = 0;
    }
    moduleClear((PyObject *)module);
}

static struct PyModuleDef moduleDefinition = {
    PyModuleDef_HEAD_INIT,
    "_ffl_gnutls",
    "Focused GnuTLS native bindings.",
    sizeof(FFLGnuTLSModuleState),
    moduleMethods,
    NULL,
    moduleTraverse,
    moduleClear,
    moduleFree
};

PyMODINIT_FUNC PyInit__ffl_gnutls(void) {
    PyObject *module;
    FFLGnuTLSModuleState *state;
    int result;

    result = fflGnuTLSInitialize();
    if (result < 0) {
        char message[256];

        fflGnuTLSFormatError(result, message, sizeof(message));
        PyErr_Format(
            PyExc_ImportError,
            "ffl_gnutls initialization failed: %s (%d)",
            message,
            result
        );
        return NULL;
    }

    module = PyModule_Create(&moduleDefinition);
    if (module == NULL) {
        fflGnuTLSDeinitialize();
        return NULL;
    }

    state = fflGetModuleState(module);
    state->initialized = 1;
    state->errorType = PyErr_NewException(
        "ffl_gnutls.GnuTLSError",
        NULL,
        NULL
    );
    if (state->errorType == NULL) {
        Py_DECREF(module);
        return NULL;
    }

    if (PyModule_AddObjectRef(
        module,
        "GnuTLSError",
        state->errorType
    ) != 0) {
        Py_DECREF(module);
        return NULL;
    }

    return module;
}
