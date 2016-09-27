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

/** @file

   @brief
   Wrapper library for crypto hash functions.
   Works with the following tls/crypto libraries:
   OpenSSL, Nettle, Windows crypto.
   Supports the following hashing algorithms:
   MD5, SHA1, SHA128, SHA224, SHA256, SHA384, SHA512.
 */

#include "ma_crypto.h"

static MA_CRYPTO_HASH_TYPE ma_crypt_hash_hashtype(unsigned int hash_type)
{
  switch(hash_type) {
    case MA_CRYPTO_HASH_MD5:
#if defined(HAVE_CRYPTO_OPENSSL)
      return EVP_md5();
#elif defined(HAVE_CRYPTO_NETTLE)
      return &nettle_md5;
#elif defined(HAVE_CRYPTO_BCRYPT)
      return BCRYPT_MD5_ALGORITHM;
#endif
      break;
    case MA_CRYPTO_HASH_SHA1:
#if defined(HAVE_CRYPTO_OPENSSL)
      return EVP_sha1();
#elif defined(HAVE_CRYPTO_NETTLE)
      return &nettle_sha1;
#elif defined(HAVE_CRYPTO_BCRYPT)
      return BCRYPT_MD5_ALGORITHM;
#endif    
      break;
    case MA_CRYPTO_HASH_SHA224:
#if defined(HAVE_CRYPTO_OPENSSL)    
      return EVP_sha224();
#elif defined(HAVE_CRYPTO_NETTLE)
      return &nettle_sha224;
#elif defined(HAVE_CRYPTO_BCRYPT)
      return NULL;
#endif
      break;
    case MA_CRYPTO_HASH_SHA256:
#if defined(HAVE_CRYPTO_OPENSSL)    
      return EVP_sha256();
#elif defined(HAVE_CRYPTO_NETTLE)
      return &nettle_sha256;
#elif defined(HAVE_CRYPTO_BCRYPT)
      return BCRYPT_SHA256_ALGORITHM;
#endif
      break;
    case MA_CRYPTO_HASH_SHA384:
#if defined(HAVE_CRYPTO_OPENSSL)    
      return EVP_sha384();
#elif defined(HAVE_CRYPTO_NETTLE)
      return &nettle_sha384;
#elif defined(HAVE_CRYPTO_BCRYPT)
      return BCRYPT_SHA384_ALGORITHM;
#endif
      break;
    case MA_CRYPTO_HASH_SHA512:
#if defined(HAVE_CRYPTO_OPENSSL)    
      return EVP_sha512();
#elif defined(HAVE_CRYPTO_NETTLE)
      return &nettle_sha512;
#elif defined(HAVE_CRYPTO_BCRYPT)
      return BCRYPT_SHA512_ALGORITHM;
#endif
      break;
  }
  /* unsupported hash */
  return NULL;
}

void ma_crypto_hash_init(MA_CRYPTO_HASH_CTX cctx, enum ma_crypto_hash_alg hash_alg)
{
  struct st_crypto_hash_ctx *ctx= (struct st_crypto_hash_ctx *)cctx;
  MA_CRYPTO_HASH_TYPE evp_hash;

  if (!ctx)
    return;

  evp_hash= ma_crypt_hash_hashtype(hash_alg);
#if defined(HAVE_CRYPTO_OPENSSL)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if (evp_hash && (ctx->ctx= EVP_MD_CTX_new()))
#else
  if (evp_hash && (ctx->ctx= EVP_MD_CTX_create()))
#endif
  {
    EVP_DigestInit_ex(ctx->ctx, evp_hash, NULL);
    return;
  }
#elif defined(HAVE_CRYPTO_NETTLE)
  if (evp_hash)
  {
    ctx->ctx= malloc(evp_hash->context_size);
    ctx->hash= evp_hash;
    ctx->hash->init(ctx->ctx);
    return;
  }
#elif defined(HAVE_CRYPTO_BCRYPT)
  if (evp_hash != -1)
  {
    DWORD cbObjSize, cbData;
    ctx->hAlg= ctx->hHash= ctx->hashObject= 0;
    if (BCryptOpenAlgorithmProvider(&ctx->hAlg, evp_hash, NULL, 0) < 0)
      return;
    if (BCryptGetProperty(ctx->hAlg, BCRYPT_OBJECT_LENGTH,
                      (PBYTE)&cbObjSize, sizeof(DWORD),
                      &cbData, 0) < 0)
      return;
    ctx->hashObject= (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbObjSize);
    ctx->digest_len= ma_crypto_hash_digest_size(hash_alg);
    BCryptCreateHash(ctx->hAlg, &ctx->hHash, ctx->hashObject, cbObjSize, NULL, 0, 0);
  }
#endif
}

static void ma_crypt_hash_input(MA_CRYPTO_HASH_CTX cctx,
                                const unsigned char *buf,
                                size_t len)
{
  struct st_crypto_hash_ctx *ctx= (struct st_crypto_hash_ctx *)cctx;
#if defined(HAVE_CRYPTO_OPENSSL)
  EVP_DigestUpdate(ctx->ctx, buf, len);
#elif defined(HAVE_CRYPTO_NETTLE)
  ctx->hash->update(ctx->ctx, len, buf);
#elif defined(HAVE_CRYPTO_BCRYPT)
  BCryptHashData(ctx->hHash, buf, len, 0);
#endif  
}

static void ma_crypt_hash_result(MA_CRYPTO_HASH_CTX cctx, unsigned char *digest)
{
  struct st_crypto_hash_ctx *ctx= (struct st_crypto_hash_ctx *)cctx;
#if defined(HAVE_CRYPTO_OPENSSL)
  EVP_DigestFinal_ex(ctx->ctx, digest, NULL);
#elif defined(HAVE_CRYPTO_NETTLE)
  ctx->hash->digest(ctx->ctx, ctx->hash->digest_size, digest);
#elif defined(HAVE_CRYPTO_BCRYPT)
  unsigned long len;
  BCryptFinishHash(ctx->hHash, ctx->digest, ctx->digest_len, 0);
  memcpy(digest, ctx->digest, ctx->digest_len);
#endif
}

void ma_crypto_hash_deinit(MA_CRYPTO_HASH_CTX cctx)
{
  struct st_crypto_hash_ctx *ctx= (struct st_crypto_hash_ctx *)cctx;
  if (!ctx)
    return;
#if defined(HAVE_CRYPTO_OPENSSL)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_MD_CTX_free(ctx->ctx);
#else
  EVP_MD_CTX_destroy(ctx->ctx);
#endif
  ctx->ctx= NULL;
#elif defined(HAVE_CRYPTO_NETTLE)
  if (ctx)
    free(ctx->ctx);
  ctx->ctx= NULL;
#elif defined(HAVE_CRYPTO_BCRYPT)
  if(ctx->hHash)
    BCryptDestroyHash(ctx->hHash);
  ctx->hHash= NULL;
  if(ctx->hAlg)
    BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
  if (ctx->hashObject)
    HeapFree(GetProcessHeap(), 0, ctx->hashObject);
  ctx->hAlg= NULL;
#endif
}

void ma_crypto_hash_v(enum ma_crypto_hash_alg hash_alg,
                unsigned char *digest,
                va_list args)
{
  MA_CRYPTO_HASH_CTX ctx;
  const unsigned char *str;

  if (!(ctx= ma_crypto_hash_new()))
    return;
  ma_crypto_hash_init(ctx, hash_alg);
  for (str= va_arg(args, const unsigned char*); str; 
      str= va_arg(args, const unsigned char*))
    ma_crypt_hash_input(ctx, str, va_arg(args, size_t));

  ma_crypt_hash_result(ctx, digest);
  ma_crypto_hash_deinit(ctx);
  ma_crypto_hash_free(ctx);
}

/**
  @brief wrapper function to compute hash from one or more
  buffers.

  @param hash_alg [in]    hash algorithm
  @param digest [out]     computed hash digest
  @param ... [in]         variable argument list containg touples of
  message and message lengths. Last parameter
  must be always NULL.

  @return                 void                         
 */
void ma_crypto_hashv(enum ma_crypto_hash_alg hash_alg,
                     unsigned char *digest, ...)
{
  va_list args;

  va_start(args, digest);
  ma_crypto_hash_v(hash_alg, digest, args);
  va_end(args);
}

/**
  @brief wrapper function to compute hash from message buffer

  @param hash_alg [in]   hashing hash_alg
  @param digest [out]    computed hash digest
  @param buffer [in]     message buffer
  @param length [in]     length of message buffer

  @return                void                         
 */
void ma_crypto_hash(enum ma_crypto_hash_alg hash_alg,
             unsigned char *digest,
             const unsigned char *buffer,
             size_t length)
{
  ma_crypto_hashv(hash_alg, digest, buffer, length, NULL, 0);
}

/**
  @brief wrapper function to acquire a context for hash
  calculations

  @param hash_alg [in]   hashing hash_alg

  @return                 hash context                         
 */
MA_CRYPTO_HASH_CTX ma_crypto_hash_new()
{
  return (MA_CRYPTO_HASH_CTX)malloc(sizeof(struct st_crypto_hash_ctx));
}

/**
  @brief hashes len bytes of data into the hash context.
  This function can be called several times on same context to
  hash additional data.

  @param ctx [in]       hash context
  @param buffer [in]    data buffer
  @param len [in]       size of buffer

  @return               void
*/
void ma_crypto_hash_input(MA_CRYPTO_HASH_CTX ctx, const unsigned char *buffer, size_t len)
{
  ma_crypt_hash_input(ctx, buffer, len);
}

/**
  @brief retrieves the hash value from hash context 

  @param ctx [in]       hash context
  @param digest [in]    digest containing hash value

  @return               void
*/
void ma_crypto_hash_result(MA_CRYPTO_HASH_CTX ctx,
                    unsigned char *digest)
{
  ma_crypt_hash_result(ctx, digest);
}

/**
  @brief deallocates hash context which was previoulsy allocated by
  ma_crypto_hash_new

  @param ctx [in]       hash context

  @return               void
 */
void ma_crypto_hash_free(MA_CRYPTO_HASH_CTX cctx)
{
  struct st_crypto_hash_ctx *ctx= (struct st_crypto_hash_ctx *)cctx;
#ifdef HAVE_CRYPTO_BCRYPT
  if (ctx->hAlg)
#else
  if (ctx->ctx)
#endif
    ma_crypto_hash_deinit(ctx);
  free(ctx);
}

unsigned int ma_crypto_hash_ctx_size()
{
  return (unsigned int)sizeof(struct st_crypto_hash_ctx);
}
