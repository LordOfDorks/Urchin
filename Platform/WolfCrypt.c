/*
UrchinTSS

Copyright (c) Microsoft Corporation

All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// Note: This code was derived from the TCG TPM 2.0 Library Specification at
// http://www.trustedcomputinggroup.org/resources/tpm_library_specification

#ifdef USE_WOLFCRYPT

#include "stdafx.h"

// Wolf Documentation @ https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-18-wolfcrypt-api-reference.html
#include "user_settings.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/integer.h"
#include "wolfssl/wolfcrypt/aes.h"

WC_RNG* g_platformRng = NULL;

WOLFSSL_API void* wolfSSL_Malloc(size_t size)
{
    return malloc(size);
}

WOLFSSL_API void  wolfSSL_Free(void *ptr)
{
    free(ptr);
}

WOLFSSL_API void* wolfSSL_Realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

BOOL
_cpri__RngStartup(
    void
)
{
    if ((g_platformRng == NULL) &&
        (((g_platformRng = (WC_RNG*)malloc(sizeof(WC_RNG))) == NULL) ||
        (wc_InitRng(g_platformRng) != 0)))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

CRYPT_RESULT _cpri__StirRandom(INT32 seedSize,
    BYTE *buffer)
{
    // RNG automatically reseeds from the platform
    return CRYPT_SUCCESS;
}

UINT16 _cpri__GenerateRandom(INT32 randomSize,
    BYTE *buffer)
{
    if (wc_RNG_GenerateBlock(g_platformRng, buffer, randomSize) != 0)
    {
        return 0;
    }

    return randomSize;
}

static size_t HashLength(TPM_ALG_ID hashAlg)
{
    size_t digestLen = 0;

    switch (hashAlg) {
#ifdef TPM_ALG_SHA1
    case TPM_ALG_SHA1:
        digestLen = 20;
        break;
#endif
#ifdef TPM_ALG_SHA256
    case TPM_ALG_SHA256:
        digestLen = 32;
        break;
#endif
#ifdef TPM_ALG_SHA384
    case TPM_ALG_SHA384:
        digestLen = 48;
        break;
#endif
#ifdef TPM_ALG_SHA512
    case TPM_ALG_SHA512:
        digestLen = 64;
        break;
#endif
    }
    return digestLen;
}

BOOL
_cpri__HashStartup(
    void
)
{
    return TRUE;
}

UINT16
_cpri__CopyHashState(
    CPRI_HASH_STATE *out,       // OUT: destination of the state
    CPRI_HASH_STATE *in         // IN: source of the state
)
{
    UINT16 retVal = 0;
    switch (in->hashAlg)
    {
#ifdef TPM_ALG_SHA1
    case TPM_ALG_SHA1:
        if ((out->state.data = malloc(sizeof(wc_Sha))) != NULL)
        {
            wc_ShaCopy(in->state.data, out->state.data);
        }
        break;
#endif
#ifdef TPM_ALG_SHA256
    case TPM_ALG_SHA256:
        if ((out->state.data = malloc(sizeof(wc_Sha256))) != NULL)
        {
            wc_Sha256Copy(in->state.data, out->state.data);
        }
        break;
#endif
#ifdef TPM_ALG_SHA384
    case TPM_ALG_SHA384:
        if ((out->state.data = malloc(sizeof(wc_Sha384))) != NULL)
        {
            wc_Sha384Copy(in->state.data, out->state.data);
        }
        break;
#endif
#ifdef TPM_ALG_SHA512
    case TPM_ALG_SHA512:
        if ((out->state.data = malloc(sizeof(wc_Sha512))) != NULL)
        {
            wc_Sha512Copy(in->state.data, out->state.data);
        }
        break;
#endif
    }

    out->hashAlg = in->hashAlg;
    return (out->state.data) ? sizeof(CPRI_HASH_STATE) : 0;
}

UINT16 _cpri__StartHash(TPM_ALG_ID hashAlg,
    BOOL sequence,
    PCPRI_HASH_STATE hashState)
{
    if (sequence) return 0;

    switch (hashAlg) {
#ifdef TPM_ALG_SHA1
    case TPM_ALG_SHA1:
        if ((hashState->state.data = malloc(sizeof(wc_Sha))) != NULL)
        {
            wc_InitSha((wc_Sha*)hashState->state.data);
        }
        break;
#endif
#ifdef TPM_ALG_SHA256
    case TPM_ALG_SHA256:
        if ((hashState->state.data = malloc(sizeof(wc_Sha256))) != NULL)
        {
            wc_InitSha256((wc_Sha256*)hashState->state.data);
        }
        break;
#endif
#ifdef TPM_ALG_SHA384
    case TPM_ALG_SHA384:
        if ((hashState->state.data = malloc(sizeof(wc_Sha384))) != NULL)
        {
            wc_InitSha384((wc_Sha384*)hashState->state.data);
        }
        break;
#endif
#ifdef TPM_ALG_SHA512
    case TPM_ALG_SHA512:
        if ((hashState->state.data = malloc(sizeof(wc_Sha512))) != NULL)
        {
            wc_InitSha512((wc_Sha512*)hashState->state.data);
        }
        break;
#endif
    default:
        return 0;
    }

    hashState->hashAlg = hashAlg;

    return (UINT16)HashLength(hashAlg);
}

void _cpri__UpdateHash(PCPRI_HASH_STATE hashState,
    UINT32 dataSize,
    BYTE *data)
{
    switch (hashState->hashAlg)
    {
#ifdef TPM_ALG_SHA1
    case TPM_ALG_SHA1:
        wc_ShaUpdate((wc_Sha*)hashState->state.data, data, dataSize);
        break;
#endif
#ifdef TPM_ALG_SHA256
    case TPM_ALG_SHA256:
        wc_Sha256Update((wc_Sha256*)hashState->state.data, data, dataSize);
        break;
#endif
#ifdef TPM_ALG_SHA384
    case TPM_ALG_SHA384:
        wc_Sha384Update((wc_Sha384*)hashState->state.data, data, dataSize);
        break;
#endif
#ifdef TPM_ALG_SHA512
    case TPM_ALG_SHA512:
        wc_Sha512Update((wc_Sha512*)hashState->state.data, data, dataSize);
        break;
#endif
    }
}

UINT16 _cpri__CompleteHash(PCPRI_HASH_STATE hashState,
    UINT32 dOutSize,
    BYTE *dOut)
{
    UINT32 digestLen = HashLength(hashState->hashAlg);
    BYTE digest[64] = { 0 };

    switch (hashState->hashAlg)
    {
#ifdef TPM_ALG_SHA1
    case TPM_ALG_SHA1:
        wc_ShaFinal((wc_Sha*)hashState->state.data, digest);
        memset(hashState->state.data, 0x00, sizeof(wc_Sha));
        break;
#endif
#ifdef TPM_ALG_SHA256
    case TPM_ALG_SHA256:
        wc_Sha256Final((wc_Sha256*)hashState->state.data, digest);
        memset(hashState->state.data, 0x00, sizeof(wc_Sha256));
        break;
#endif
#ifdef TPM_ALG_SHA384
    case TPM_ALG_SHA384:
        wc_Sha384Final((wc_Sha384*)hashState->state.data, digest);
        memset(hashState->state.data, 0x00, sizeof(wc_Sha384));
        break;
#endif
#ifdef TPM_ALG_SHA512
    case TPM_ALG_SHA512:
        wc_Sha512Final((wc_Sha512*)hashState->state.data, digest);
        memset(hashState->state.data, 0x00, sizeof(wc_Sha512));
        break;
#endif
    default:
        digestLen = 0;
        break;
    }
    free(hashState->state.data);
    memcpy(dOut, digest, MIN(digestLen, dOutSize));

    return (UINT16)MIN(digestLen, dOutSize);
}

UINT16 _cpri__HashBlock(TPM_ALG_ID hashAlg,
    UINT32 dataSize,
    BYTE* data,
    UINT32 digestSize,
    BYTE* digest)
{
    if (digestSize >= HashLength(hashAlg))
    {
        switch (hashAlg)
        {
#ifdef TPM_ALG_SHA1
        case TPM_ALG_SHA1:
        {
            wc_Sha context = { 0 };
            wc_InitSha(&context);
            wc_ShaUpdate(&context, data, dataSize);
            wc_ShaFinal(&context, digest);
            break;
        }
#endif
#ifdef TPM_ALG_SHA256
        case TPM_ALG_SHA256:
        {
            wc_Sha256 context = { 0 };
            wc_InitSha256(&context);
            wc_Sha256Update(&context, data, dataSize);
            wc_Sha256Final(&context, digest);
            break;
        }
#endif
#ifdef TPM_ALG_SHA384
        case TPM_ALG_SHA384:
        {
            wc_Sha384 context = { 0 };
            wc_InitSha384(&context);
            wc_Sha384Update(&context, data, dataSize);
            wc_Sha384Final(&context, digest);
            break;
        }
#endif
#ifdef TPM_ALG_SHA512
        case TPM_ALG_SHA512:
        {
            wc_Sha512 context = { 0 };
            wc_InitSha512(&context);
            wc_Sha512Update(&context, data, dataSize);
            wc_Sha512Final(&context, digest);
            break;
        }
#endif
        }

        return (UINT16)HashLength(hashAlg);
    }
    else
    {
        return 0;
    }
}

BOOL
_cpri__RsaStartup(
    void
)
{
    return TRUE;
}

CRYPT_RESULT
_cpri__TestKeyRSA(
    TPM2B* dOut,
    UINT32 exponent,
    TPM2B* publicKey,
    TPM2B* prime1,
    TPM2B* prime2
)
{
    CRYPT_RESULT retVal = CRYPT_SUCCESS;
    long exp = (!exponent) ? 0x00010001 : (long)exponent;
    mp_int e = { 0 };
    mp_int d = { 0 };
    mp_int n = { 0 };
    mp_int p = { 0 };
    mp_int q = { 0 };
    mp_int qr = { 0 };
    mp_int tmp1 = { 0 };
    mp_int tmp2 = { 0 };

    if (publicKey->size / 2 != prime1->size)
        return CRYPT_PARAMETER;

    if ((mp_init_multi(&e, &d, &n, &p, &q, &qr) != 0) ||
        (mp_init_multi(&tmp1, &tmp2, NULL, NULL, NULL, NULL) != 0))
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }
    if (mp_set_int(&e, exp) != 0)  /* key->e = exp */
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }

    // Read the first prime
    if (mp_read_unsigned_bin(&p, (const unsigned char*)prime1->buffer, prime1->size) != 0)
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }

    // If prime2 is provided, then compute n
    if ((prime2 != NULL) && (prime2->size != 0))
    {
        // Two primes provided so use them to compute n
        if (mp_read_unsigned_bin(&q, (const unsigned char*)prime2->buffer, prime2->size) != 0)
        {
            retVal = CRYPT_PARAMETER;
            goto Cleanup;
        }

        // Make sure that the sizes of the primes are compatible
        if (mp_unsigned_bin_size(&q) != mp_unsigned_bin_size(&p))
        {
            retVal = CRYPT_PARAMETER;
            goto Cleanup;
        }

        // Multiply the primes to get the public modulus
        if (mp_mul(&p, &q, &n) != 0)
        {
            retVal = CRYPT_FAIL;
            goto Cleanup;
        }

        // if the space provided for the public modulus is large enough,
        // save the created value
        if ((mp_unsigned_bin_size(&n) == publicKey->size) &&
            (mp_to_unsigned_bin(&n, publicKey->buffer) != 0))
        {
            retVal = CRYPT_PARAMETER;
            goto Cleanup;
        }
    }
    else
    {
        // One prime provided so find the second prime by division
        if (mp_read_unsigned_bin(&n, (const unsigned char*)publicKey->buffer, publicKey->size) != 0)
        {
            retVal = CRYPT_PARAMETER;
            goto Cleanup;
        }

        // Get q = n/p;
        if (mp_div(&n, &p, &q, &qr) != 0)
        {
            retVal = CRYPT_FAIL;
            goto Cleanup;
        }

        // If there is a remainder, then this is not a valid n
        if (mp_unsigned_bin_size(&qr) != 0 || mp_count_bits(&q) != mp_count_bits(&p))
        {
            retVal = CRYPT_PARAMETER;
            goto Cleanup;
        }

        // Return the second prime if requested
        if (prime2 != NULL)
        {
            prime2->size = mp_unsigned_bin_size(&q);
            mp_to_unsigned_bin(&q, prime2->buffer);
        }
    }

    // We have both primes now
    if ((mp_sub_d(&q, 1, &tmp1) != 0) ||    /* tmp1 = q-1 */
        (mp_sub_d(&p, 1, &tmp2) != 0) ||    /* tmp2 = p-1 */
        (mp_lcm(&tmp1, &tmp2, &tmp1) != 0)) /* tmp1 = lcm(p-1, q-1) */
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

    // Calculate the private key
    if (mp_invmod(&e, &tmp1, &d) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

    // Return the private key
    dOut->size = mp_unsigned_bin_size(&d);
    mp_to_unsigned_bin(&d, dOut->buffer);

Cleanup:
    mp_clear(&e);
    mp_clear(&d);
    mp_clear(&n);
    mp_clear(&p);
    mp_clear(&q);
    mp_clear(&qr);
    mp_clear(&tmp1);
    mp_clear(&tmp2);
    return retVal;
}

CRYPT_RESULT RSAEP(size_t dInOutSize,
    const void* dInOut,
    RSA_KEY* key)
{
    CRYPT_RESULT retVal = CRYPT_SUCCESS;
    long exp = (!key->exponent) ? 0x00010001 : (long)key->exponent;
    mp_int e = { 0 };
    mp_int n = { 0 };
    mp_int tmp = { 0 };
    UINT32 offset = (UINT32)dInOutSize;

    // Set up the public key
    if (mp_init_multi(&e, &n, &tmp, NULL, NULL, NULL) != 0)
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }
    if (mp_set_int(&e, exp) != 0)
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }
    if (mp_read_unsigned_bin(&n, (const unsigned char*)key->publicKey->buffer, (int)key->publicKey->size) != 0)
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }

    // Perform the encryption
    if ((mp_read_unsigned_bin(&tmp, (const unsigned char*)dInOut, (int)dInOutSize) != 0) ||
        (mp_exptmod(&tmp, &e, &n, &tmp) != 0))
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

    // Prepare the output
    memset((BYTE*)dInOut, 0x00, dInOutSize);
    offset -= mp_unsigned_bin_size(&tmp);
    if (mp_to_unsigned_bin(&tmp, &((unsigned char*)dInOut)[offset]) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

Cleanup:
    mp_clear(&e);
    mp_clear(&n);
    mp_clear(&tmp);
    return retVal;
}

CRYPT_RESULT RSADP(size_t dInOutSize,
    const void* dInOut,
    RSA_KEY* key)
{
    BOOL retVal = TRUE;
    mp_int d = { 0 };
    mp_int n = { 0 };
    mp_int tmp = { 0 };
    UINT32 offset = (UINT32)dInOutSize;

    // Set up the private key
    if (mp_init_multi(&d, &n, &tmp, NULL, NULL, NULL) != 0)
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }
    if (mp_read_unsigned_bin(&n, (const unsigned char*)key->publicKey->buffer, (int)key->publicKey->size) != 0)
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }
    if (mp_read_unsigned_bin(&d, (const unsigned char*)key->privateKey->buffer, (int)key->privateKey->size) != 0)
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }

    // Perform the decryption
    if ((mp_read_unsigned_bin(&tmp, (const unsigned char*)dInOut, (int)dInOutSize) != 0) ||
        (mp_exptmod(&tmp, &d, &n, &tmp) != 0))
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

    // Prepare the output
    memset((BYTE*)dInOut, 0x00, dInOutSize);
    offset -= mp_unsigned_bin_size(&tmp);
    if (mp_to_unsigned_bin(&tmp, &((unsigned char*)dInOut)[offset]) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

Cleanup:
    mp_clear(&d);
    mp_clear(&n);
    mp_clear(&tmp);
    return retVal;
}


BOOL
_cpri__SymStartup(
    void
)
{
    return TRUE;
}

CRYPT_RESULT
AES_create_key(const unsigned char *userKey,
    const int bits,
    PVOID *key)
{
    TPM2B* keyContext = NULL;
    size_t contextSize;

    contextSize = sizeof(TPM2B) - sizeof(BYTE) + bits / 8 + 1;

    // Remember the key
    if ((keyContext = (TPM2B*)malloc(contextSize)) != NULL)
    {
        keyContext->size = bits / 8;
        memcpy(keyContext->buffer, userKey, keyContext->size);
        *key = keyContext;
    }

    return (keyContext) ? CRYPT_SUCCESS : CRYPT_FAIL;
}

CRYPT_RESULT
AES_destroy_key(PVOID key)
{
    TPM2B* keyContext = (TPM2B*)key;
    memset(keyContext, 0x00, sizeof(TPM2B));
    free(keyContext);
    return CRYPT_SUCCESS;
}

CRYPT_RESULT
AES_encrypt(const unsigned char *in,
    unsigned char *out,
    PVOID key)
{
    TPM2B* keyContext = (TPM2B*)key;
    Aes aesKey = { 0 };
    BYTE iv[AES_BLOCK_SIZE] = { 0 };
    if (wc_AesSetKey(&aesKey, keyContext->buffer, keyContext->size, iv, AES_ENCRYPTION) != 0)
    {
        return CRYPT_FAIL;
    }
    wc_AesEncryptDirect(&aesKey, out, in);
    memset(&aesKey, 0x00, sizeof(aesKey));
    return CRYPT_SUCCESS;
}

CRYPT_RESULT
AES_decrypt(const unsigned char *in,
    unsigned char *out,
    PVOID key)
{
    TPM2B* keyContext = (TPM2B*)key;
    Aes aesKey = { 0 };
    BYTE iv[AES_BLOCK_SIZE] = { 0 };
    if (wc_AesSetKey(&aesKey, keyContext->buffer, keyContext->size, iv, AES_DECRYPTION) != 0)
    {
        return CRYPT_FAIL;
    }
    wc_AesDecryptDirect(&aesKey, out, in);
    memset(&aesKey, 0x00, sizeof(aesKey));
    return CRYPT_SUCCESS;
}

void
_cpri__ReleaseCrypt(
    void
)
{
    if (g_platformRng != NULL)
    {
        free(g_platformRng);
        g_platformRng = NULL;
    }
}

#endif //USE_WOLFCRYPT