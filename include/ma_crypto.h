/* Copyright (c) 2016 Georg Richter and MariaDB Corporation AB

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not see <http://www.gnu.org/licenses>
   or write to the Free Software Foundation, Inc., 
   51 Franklin St., Fifth Floor, Boston, MA 02110, USA */

#ifndef _ma_crypto_h
#define _ma_crypto_h

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @file

   @brief
   Include file for for cryptographic wrapper functions.
*/

/*! block cipher modes: Supported key sizes are 128, 192 and 256 bits */
enum ma_crypto_aes_mode {
  MA_AES_ECB, /*!< Electronic codebook mode */
  MA_AES_CBC, /*!< Cipher block chaining mode */
  MA_AES_GCM, /*!< Galois/counter mode */
  MA_AES_CTR  /*!< Counter mode */
};

/*! hash type enumeration */
enum ma_crypto_hash_alg {
  MA_CRYPTO_HASH_MD5= 0,  /*!< MD5 hash (128-bit, 16 bytes)  */
  MA_CRYPTO_HASH_SHA1,    /*!< SHA1 hash (160-bit, 20 bytes) */
  MA_CRYPTO_HASH_SHA224,  /*!< SHA224 hash (224-bit, 28 bytes) */
  MA_CRYPTO_HASH_SHA256,  /*!< SHA256 hash (256-bit, 32 bytes) */
  MA_CRYPTO_HASH_SHA384,  /*!< SHA384 hash (384-bit, 48 bytes) */
  MA_CRYPTO_HASH_SHA512,  /*!< SHA512 hash (512-bit, 64 bytes) */
};

#define MA_CRYPTO_MD5_HASH_SIZE 16
#define MA_CRYPTO_SHA1_HASH_SIZE 20
#define MA_CRYPTO_SHA224_HASH_SIZE 28
#define MA_CRYPTO_SHA256_HASH_SIZE 32
#define MA_CRYPTO_SHA384_HASH_SIZE 48
#define MA_CRYPTO_SHA512_HASH_SIZE 64

/* Windows doesn't support SHA224 hashing algorithm */
#ifndef HAVE_CRYPTO_BCRYPT
#define HAVE_SHA224
#endif

static const size_t ma_crypto_hash_sizes[]= {
  MA_CRYPTO_MD5_HASH_SIZE,
  MA_CRYPTO_SHA1_HASH_SIZE,
  MA_CRYPTO_SHA224_HASH_SIZE,
  MA_CRYPTO_SHA256_HASH_SIZE,
  MA_CRYPTO_SHA384_HASH_SIZE,
  MA_CRYPTO_SHA512_HASH_SIZE
};

#define MA_CRYPTO_MAX_HASH_SIZE MA_CRYPTO_SHA512_HASH_SIZE


/** \def encryption/decryption flags. */
#define MA_CRYPTO_ENCRYPT  1 /*!< encrypt */
#define MA_CRYPTO_DECRYPT  2 /*!< decrypt */
#define MA_CRYPTO_NOPAD    4 /*!< don't pad automatically during encryption */

#define MA_AES_BLOCK_SIZE AES_BLOCK_SIZE
#define MA_AES_MAX_KEY_LENGTH 32

#define MY_AES_ECB MA_AES_ECB
#define MY_AES_CBC MA_AES_CBC
#define MY_AES_GCM MA_AES_GCM
#define MY_AES_CTR MA_AES_CTR

#define MY_AES_OK MA_CRYPTO_OK

/** \def crypto errors */
#define MA_CRYPTO_OK        0
#define MA_CRYPTO_EINVKEY   1
#define MA_CRYPTO_EINVCTX   2
#define MA_CRYPTO_ENOMEM    3
#define MA_CRYPTO_EINVIV    4
#define MA_CRYPTO_EINVCIPH  5
#define MA_CRYPTO_EBADDATA  6
#define MA_CRYPTO_ERND      7

#include <ma_crypto_internal.h>

/** \typedef MariaDB crypto context */
typedef void *MA_CRYPTO_CRYPT_CTX;
/** \typedef MariaDB hash context */
typedef void *MA_CRYPTO_HASH_CTX;

/* function prototypes */

/**
  @brief acquire a context for encryption
  and decryption. To prevent memory leaks the context must be
  released via ma_crypto_crypt_free

  @return                 crypt context or NULL on error
*/
MA_CRYPTO_CRYPT_CTX ma_crypto_crypt_new();

/**
  @brief Frees a crypt context.
  
  @param[in] cctx       A crypto context which was previously allocated by
                        ma_crypto_crypt_new.
  
  @return               void
*/
void ma_crypto_crypt_free(MA_CRYPTO_CRYPT_CTX cctx);

/**
  @brief initializes the encryption context

  @param[in] cctx       A crypto context which was previously allocated by ma_crypto_new()
                        or initialized by ma_crypto_crypt_init
  @param[in] mode       block cipher mode
  @param[in] flags      operation flags: MA_CRYPTO_ENCRYPT or MA_CRYPTO_DECRYPT.
                        these flags can be combined with MA_CRYPTO_NOPAD to disable
                        automatic padding
  @param[in] key        encryption/decryption key.
  @param[in] klen       key length. Only 16, 24 and 32 bit keys are supported.
  @param[in] iv         initialization vector. When using GCM mode this vector will contain
                        also the authentication data (beginning at offset 13)
  @param[in] ivlen     length of initialization vector                 
  @return               MA_CRYPTO_OK on success
                        MA_CRYPTO_EINVCTX if crypto context is invalid or NULL
                        MA_CRYPTO_EINVKEY if an invalid key was used
                        MA_CRYPTO_EINVIV if an invalid initalization vector was used
                        MA_CRYPTO_ENOMEM if not enough memory was available
                        MA_CRYPTO_BADDATA if the encryption or decryption operation failed
*/
int ma_crypto_crypt_init(MA_CRYPTO_CRYPT_CTX cctx,
                         enum ma_crypto_aes_mode mode,
                         int flags,
                         const unsigned char *key,
                         unsigned int key_len,
                         const unsigned char *iv,
                         unsigned int iv_len);

/**
  @brief perform encryption or decryption operation. The mode depends on the mode flag
         which was previously passed to ma_crypto_init function.

  @param[in] cctx       A crypto context which was previously allocated by ma_crypto_new()
                        or initialized by ma_crypto_crypt_init
  @param[in] src        depending on flags this buffer contains cleartext or ciphertext
                        data
  @param[in] slen       length of buffer
  @param[out] dst       destination buffer which contains result of crypt operation. Depending on
                        the block cipher and pad mode this buffer must be larger than slen.
  @param[out] dlen      length of destination buffer after update operation. The total length after
                        crypt operation can be determind by sum of dlen values from update and finish.

  @return               MA_CRYPTO_OK on success
                        MA_CRYPTO_EINVKEY if an invalid key was used
                        MA_CRYPTO_EINVIV if an invalid initalization vector was used
                        MA_CRYPTO_ENOMEM if not enough memory was available
                        MA_CRYPTO_BADDATA if the encryption or decryption operation failed
*/
int ma_crypto_crypt_update(MA_CRYPTO_CRYPT_CTX cctx,
                           const unsigned char *src,
                           unsigned int slen,
                           unsigned char *dst,
                           unsigned int *dlen);

/**
  @brief finishes encryption or decryption operation.

  @param[in] cctx       A crypto context which was previously allocated by ma_crypto_new()
                        or initialized by ma_crypto_crypt_init
  @param[out] dst       destination buffer which contains result of crypt operation. This value is
                        usually the destination buffer passed to ma_crypto_update plus the length
                        returned by ma_crypto_update.
  @param[out] dlen      length of destination buffer after update operation. The total length after
                        crypt operation can be determind by sum of dlen values from update and finish.
  @return               MA_CRYPTO_OK on success
                        MA_CRYPTO_EINVKEY if an invalid key was used
                        MA_CRYPTO_EINVIV if an invalid initalization vector was used
                        MA_CRYPTO_ENOMEM if not enough memory was available
                        MA_CRYPTO_BADDATA if the encryption or decryption operation failed
*/
int ma_crypto_crypt_finish(MA_CRYPTO_CRYPT_CTX cctx,
                           unsigned char *dst,
                           unsigned int *dlen);
/**
  @brief encrypts or decrypts a buffer in one step

  @param[in] mode       block cipher mode
  @param[in] flags      operation flags: MA_CRYPTO_ENCRYPT or MA_CRYPTO_DECRYPT.
                        these flags can be combined with MA_CRYPTO_NOPAD to disable
                        automatic padding
  @param[in] src        depending on flags this buffer contains cleartext or ciphertext
                        data
  @param[in] slen       length of buffer
  @param[out] dst       destination buffer which contains result of crypt operation
  @param[out] dlen      final length of destination buffer after crypt operation
  @param[in] key        encryption/decryption key.
  @param[in] klen       key length. Only 16, 24 and 32 bit keys are supported.
  @param[in] iv         initialization vector. When using GCM mode this vector will contain
                        also the authentication data (beginning at offset 13)
  @param[in] ivlen      length of initialization vector
  @return               MA_CRYPTO_OK on success
                        MA_CRYPTO_EINVKEY if an invalid key was used
                        MA_CRYPTO_EINVIV if an invalid initalization vector was used
                        MA_CRYPTO_ENOMEM if not enough memory was available
                        MA_CRYPTO_BADDATA if the encryption or decryption operation failed
*/
int ma_crypto_crypt(enum ma_crypto_aes_mode mode,
                    int flags,
                    const unsigned char *src,
                    unsigned int slen,
                    unsigned char *dst,
                    unsigned int *dlen,
                    const unsigned char *key,
                    unsigned int klen,
                    const unsigned char *iv,
                    unsigned int ivlen);

/**
  @brief returns the size of context.
         After allocating memory for the context context must be initialized
         with ma_crypto_crypt_init().

  @param[in] unused1    unused
  @param[in] unused2    unused

  @return    size of crypto context

*/
unsigned int ma_crypto_crypt_ctx_size(unsigned int unused1, unsigned int unuse);

/**
  @brief generates a random number

  @param[out] buf       buffer which will be filled with a random number
  @param[in]  num       number of bytes

  @return    size of crypto context
*/
int ma_crypto_random_bytes(unsigned char* buf, int num);

/**
  @brief calculates required size for digest depending
  on the specified block cipher mode.

  @param[in]  mode          block cipher mode
  @param[in]  slen          length of source (in bytes)

  @return     digest size
*/
static inline size_t ma_crypto_crypt_digest_size(enum ma_crypto_aes_mode mode,
                                                 unsigned int slen)
{
  if (mode == MA_AES_CTR)
    return slen;
  if (mode == MA_AES_GCM)
    return slen + AES_BLOCK_SIZE;
  return (slen / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
}

/**
  @brief deinitializes context buffer

  @param[in]   cctx    context buffer

  @return              void
*/
void ma_crypto_crypt_deinit(MA_CRYPTO_CRYPT_CTX cctx);

/**
  @brief wrapper function to acquire a context for hash
  calculations

  @return                 hash context                         
 */
MA_CRYPTO_HASH_CTX ma_crypto_hash_new();

/**
  @brief hashes len bytes of data into the hash context.
  This function can be called several times on same context to
  hash additional data.

  @param[in] ctx        hash context
  @param[in] buffer     data buffer
  @param[in] len        size of buffer

  @return               void
*/
void ma_crypto_hash_input(MA_CRYPTO_HASH_CTX ctx,
                          const unsigned char *buffer,
                          size_t len);

/**
  @brief retrieves the hash value from hash context 

  @param[in] ctx        hash context
  @param[out] digest    digest containing hash value

  @return               void
 */
void ma_crypto_hash_result(MA_CRYPTO_HASH_CTX ctx, unsigned char *digest);

/**
  @brief deallocates hash context which was previoulsy allocated by
  ma_crypto_hash_new

  @param[in] ctx        hash context

  @return               void
 */
void ma_crypto_hash_free(MA_CRYPTO_HASH_CTX ctx);

/**
  @brief wrapper function to compute hash from one or more
  buffers.

  @param[in] hash_alg ]   hashing hash_alg
  @param[out] digest]     computed hash digest
  @param[in] ...          variable argument list containg touples of
                          message and message lengths. Last parameter
                          must be always NULL.

  @return                 void
 */
void ma_crypto_hash_v(enum ma_crypto_hash_alg hash_alg,
                unsigned char *digest,
                va_list args);

void ma_crypto_hash_deinit(MA_CRYPTO_HASH_CTX ctx);
void ma_crypto_hashv(enum ma_crypto_hash_alg hash_alg,
                     unsigned char *digest, ...);
/**
  @brief wrapper function to compute hash from message buffer

  @param[in] hash_alg   hash algorithm
  @param[out] digest    computed hash digest
  @param[in] buffer     message buffer
  @param[in] length     length of message buffer

  @return               void                         
*/
void ma_crypto_hash(enum ma_crypto_hash_alg hash_alg,
                     unsigned char *digest,
                     const unsigned char *buffer,
                     size_t length);
/**
  @brief return digest size for given hash algorithm

  @param[in] hash_alg    hash algorithm

  @return                length of digest                         
*/
static inline size_t ma_crypto_hash_digest_size(enum ma_crypto_hash_alg hash_alg)
{
  return ma_crypto_hash_sizes[hash_alg];
}

/**
  @brief frees hash context

  @param[in]   ctx       hash context

  @return                void
*/
void ma_crypto_hash_free(MA_CRYPTO_HASH_CTX ctx);

/**
  @brief initializes hash context

  @param[in]   ctx       hash context
  @paran[in]   hash_alg  hash algorithm

  @return                void
*/
void ma_crypto_hash_init(MA_CRYPTO_HASH_CTX ctx, enum ma_crypto_hash_alg hash_alg);

/**
  @brief deinitializes hash context

  @param[in]   ctx       hash context

  @return                void
*/
void ma_crypto_hash_deinit(MA_CRYPTO_HASH_CTX cctx);

/**
  @brief returns size of hash context

  @return        hash context size 
*/
unsigned int ma_crypto_hash_ctx_size();

#ifdef __cplusplus
}
#endif
#endif /* _ma_crypto_h */
