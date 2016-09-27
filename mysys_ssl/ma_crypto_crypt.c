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

#include <stdlib.h>
#include <ma_crypto.h>
#include <assert.h>

#if defined(HAVE_CRYPTO_NETTLE)
static const void *ma_nettle_ciphers[MA_AES_CTR + 1][3]= {
  { &nettle_aes128, &nettle_aes192, &nettle_aes256 },
  { &nettle_aes128, &nettle_aes192, &nettle_aes256 },
  { &nettle_gcm_aes128, &nettle_gcm_aes192, &nettle_gcm_aes256 },
  { &nettle_aes128, &nettle_aes192, &nettle_aes256 }
};
#elif defined(HAVE_CRYPTO_OPENSSL)
#define make_aes_dispatcher(mode)                               \
  static inline const EVP_CIPHER *aes_ ## mode(uint klen)       \
{                                                             \
  switch (klen) {                                             \
    case 16: return EVP_aes_128_ ## mode();                     \
    case 24: return EVP_aes_192_ ## mode();                     \
    case 32: return EVP_aes_256_ ## mode();                     \
    default: return 0;                                          \
  }                                                           \
}

  make_aes_dispatcher(ecb)
  make_aes_dispatcher(cbc)
  make_aes_dispatcher(ctr)
  make_aes_dispatcher(gcm)

  const EVP_CIPHER *(*openssl_ciphers[])(uint)= {
    aes_ecb, 
    aes_cbc,
    aes_gcm,
    aes_ctr
  };

#elif defined(HAVE_CRYPTO_BCRYPT)
#pragma comment(lib, "bcrypt")
static const WCHAR *bcrypt_chain_modes[MA_AES_CTR + 1] = {
  BCRYPT_CHAIN_MODE_ECB,
  BCRYPT_CHAIN_MODE_CBC,
  BCRYPT_CHAIN_MODE_GCM,
  BCRYPT_CHAIN_MODE_ECB /* since bcrypt doesn't support CTR we
                           encrypt with ecb and handle counter
                           internally */
};

#endif

/* {{{ ma_crypto_nettle_pkcs7_pad 

   Simple PKCS7 padding implementation, as described in RFC 5652
   The value of each byte added is the number of bytes added:

   03 04 05 01 02 04 01 F1 08 08 08 08 08 08 08 08

   If the length is a multiple of blocksize, and entire block of size
   block size will be added or removed

   if mode is set (=add) size of source must be at least len + blocksize.

   This function is used for nettle only.
 */
#ifdef HAVE_CRYPTO_NETTLE
static void ma_crypto_nettle_pkcs7_pad(unsigned char *src,
    unsigned int *len,
    unsigned int block_size,
    unsigned char add)
{
  if (add)
  {
    unsigned int new_len;
    unsigned char pad;

    new_len= (*len / block_size + 1) * block_size;
    pad= new_len - *len;

    memset((char *)src + *len, pad, (size_t)pad);
    *len= new_len;
  } else {
    unsigned char pad[AES_BLOCK_SIZE];
    unsigned char pad_len= *(src - 1);
    memset(pad, pad_len, pad_len);
    if (memcmp(src - pad_len, pad, pad_len) == 0)
      *len= -pad_len;
  }
}
#endif
/* }}} */

/* {{{ ma_crypto_internal_pad 

   internal padding: 
   We don't fill up to the next blocksize but en/decrypt the remaining bytes
   with XOR operation
*/
static unsigned int ma_crypto_internal_pad(MA_CRYPTO_CRYPT_CTX cctx,
    unsigned char *src,
    unsigned char *dst,
    unsigned int *slen)
{
  struct st_crypto_crypt_ctx *ctx= (struct st_crypto_crypt_ctx *)cctx;
  unsigned char mask[AES_BLOCK_SIZE];
  unsigned int i, masklen, pad_len;
  pad_len= *slen % AES_BLOCK_SIZE;

  if (!pad_len)
    return 0;

  *slen-= pad_len;

  ma_crypto_crypt(MA_AES_ECB, MA_CRYPTO_ENCRYPT | MA_CRYPTO_NOPAD,
      ctx->iv, ctx->iv_len, mask, &masklen, ctx->key, ctx->key_len, 0, 0);
  for (i=0; i < pad_len; i++)
    dst[*slen + i]= src[*slen + i] ^ mask[i];
  return pad_len;
}
/* }}} */

#ifdef HAVE_CRYPTO_NETTLE
/* {{{ ma_crypto_nettle_context_size

   calculates the size of internal nettle context, depending
   on mode and key_size
*/
static unsigned int ma_crypto_nettle_ctx_size(unsigned int mode, unsigned int key_idx)
{
  if (mode == MA_AES_GCM)
    return ((struct nettle_aead *)ma_nettle_ciphers[mode][key_idx])->context_size;
  return ((struct nettle_cipher *)ma_nettle_ciphers[mode][key_idx])->context_size;
}
#endif
/* }}} */

/* {{{ ma_crypto_ctx_set_cipher

   assigns a cipher to the given context. The cipher is 
   described by block mode (mode) and key length in bytes.
   Currently the following ciphers are supported:
   AES-ECB (128, 192 and 256 bits)
   AES-CBC (128, 192 and 256 bits)
   AES-GCM (128, 192 and 256 bits)
   AES-CTR (128, 192 and 256 bits)
 */    
static int ma_crypto_ctx_set_cipher(struct st_crypto_crypt_ctx *ctx,
                                    enum ma_crypto_aes_mode mode,
                                    unsigned int key_idx,
                                    int flags __attribute__((unused)),
                                    const unsigned char *key __attribute__((unused)),
                                    unsigned int key_len __attribute__((unused)),
                                    const unsigned char *iv __attribute__((unused)),
                                    unsigned int iv_len __attribute__((unused)))
{
  /* check if block cipher mode is valid */
  if (mode < MA_AES_ECB || mode > MA_AES_CTR)
    return MA_CRYPTO_EINVCIPH;

#ifdef HAVE_CRYPTO_NETTLE
  switch (mode) {
    case MA_AES_ECB:
    case MA_AES_CTR:
    case MA_AES_CBC:
      ctx->cipher.c= (struct nettle_cipher *)ma_nettle_ciphers[mode][key_idx];
      break;
    case MA_AES_GCM:
      ctx->cipher.a= (struct nettle_aead *)ma_nettle_ciphers[mode][key_idx];
      break;
  }
#elif defined(HAVE_CRYPTO_OPENSSL)
  {
    if (!EVP_CipherInit(ctx->ctx, openssl_ciphers[mode](key_idx * 8 + 16),
          key, iv, (flags & MA_CRYPTO_ENCRYPT) ? 1 : 0))
      return MA_CRYPTO_EINVCIPH;
  }
#elif defined(HAVE_CRYPTO_BCRYPT)
  {
    DWORD cbKeyObject,
          cbData;
    NTSTATUS status;

    /* create key object */
    if (BCryptGetProperty(ctx->AlgHdl, BCRYPT_OBJECT_LENGTH,
          (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0)< 0)
      return MA_CRYPTO_EINVKEY;
    ctx->pKey = (PBYTE)HeapAlloc (GetProcessHeap (), 0, cbKeyObject);
    /* create iv object */
    if (mode != MA_AES_ECB && iv && iv_len)
    {
      DWORD real_len= iv_len;
      status= BCryptGetProperty(ctx->AlgHdl, BCRYPT_BLOCK_LENGTH, (PBYTE)&ctx->blocklen, sizeof(DWORD), &cbData, 0);
      if (status < 0)
        return MA_CRYPTO_EINVIV;
      ctx->pIv= (PBYTE)HeapAlloc(GetProcessHeap(), 0, ctx->blocklen);
      /* for shorter iv's and gcm iv initialize iv */
      memset(ctx->pIv, 0, ctx->blocklen);
      if (mode == MA_AES_GCM)
        iv_len= 12;

      memcpy(ctx->pIv, iv, iv_len);

      if (mode == MA_AES_GCM)
      {
        BCRYPT_INIT_AUTH_MODE_INFO(ctx->authinfo);
        ctx->authinfo.pbNonce = ctx->pIv;
        ctx->authinfo.cbNonce = 12;
        ctx->authinfo.pbAuthData = (unsigned char *)iv + 12;
        ctx->authinfo.cbAuthData = real_len - 12;
        ctx->authinfo.cbTag= AES_BLOCK_SIZE;
        ctx->authinfo.pbMacContext = NULL;
        ctx->authinfo.cbMacContext = 0;
        ctx->authinfo.cbAAD = 0;
        ctx->authinfo.cbData = 0;
        ctx->authinfo.dwFlags = 0;
      }
    }

    /* set chaining mode */
    status = BCryptSetProperty(ctx->AlgHdl, BCRYPT_CHAINING_MODE, (PBYTE)bcrypt_chain_modes[mode],
                               sizeof(bcrypt_chain_modes[mode]), 0);
    if (status < 0)
      return MA_CRYPTO_EINVCIPH;
 
    /* load symmetric key */
    status= BCryptGenerateSymmetricKey(ctx->AlgHdl, &ctx->KeyHdl, ctx->pKey, cbKeyObject, (PBYTE)key, key_len, 0);
    if (status < 0)
      return MA_CRYPTO_EINVKEY;

    /* Load IV: we don't use original iv since it might be modified during crypt operation */
    if (iv)
      memcpy(ctx->pIv, iv, ctx->blocklen);
  }
#endif
  ctx->mode= mode;
  return MA_CRYPTO_OK;
}
/* }}} */

/* {{{ ma_crypto_new */
MA_CRYPTO_CRYPT_CTX ma_crypto_crypt_new()
{
  MA_CRYPTO_CRYPT_CTX ctx= calloc(1, sizeof(struct st_crypto_crypt_ctx));
  return ctx;
}
/* }}} */

/* {{{ ma_crypto_init */
int ma_crypto_crypt_init(MA_CRYPTO_CRYPT_CTX cctx,
    enum ma_crypto_aes_mode mode,
    int flags,
    const unsigned char *key,
    unsigned int key_len,
    const unsigned char *iv,
    unsigned int iv_len)
{
  struct st_crypto_crypt_ctx *ctx= (struct st_crypto_crypt_ctx *)cctx;
  int rc= MA_CRYPTO_OK;
  unsigned key_idx= (key_len - 16) / 8;

  /* check key size: valid values are 16, 24 and 32 */
  if (key_idx > 2)
    return MA_CRYPTO_EINVKEY;

  if (!ctx)
    return MA_CRYPTO_EINVCTX;
#ifdef HAVE_CRYPTO_NETTLE    
    if (!(ctx->ctx= malloc(ma_crypto_nettle_ctx_size(mode, key_idx))))
#elif defined(HAVE_CRYPTO_OPENSSL)
    if (!(ctx->ctx= EVP_CIPHER_CTX_new()))
#elif defined(HAVE_CRYPTO_BCRYPT)
      if (BCryptOpenAlgorithmProvider(&ctx->AlgHdl, BCRYPT_AES_ALGORITHM, NULL, 0) < 0)
#endif
      {
        rc= MA_CRYPTO_ENOMEM;
        goto fail;
      }

  if ((rc= ma_crypto_ctx_set_cipher(ctx, mode, key_idx, flags, key, key_len, iv, iv_len)))
    goto fail;


#ifdef HAVE_CRYPTO_NETTLE
  switch (mode) {
    case MA_AES_CTR:
      /* ctr mode uses encrypt key for en- and decryption */
      ctx->cipher.c->set_encrypt_key(ctx->ctx, key);
      break;
    case MA_AES_GCM:
      if (flags & MA_CRYPTO_ENCRYPT)
        ctx->cipher.a->set_encrypt_key(ctx->ctx, key);
      else
        ctx->cipher.a->set_decrypt_key(ctx->ctx, key);

      if (iv && ctx->cipher.a->set_nonce)
        ctx->cipher.a->set_nonce(ctx->ctx, iv);
      if (iv_len > GCM_IV_SIZE)
        ctx->cipher.a->update(ctx->ctx, iv_len - GCM_IV_SIZE, iv + GCM_IV_SIZE);
      else
        ctx->cipher.a->update(ctx->ctx, 0, NULL);
      break;
    case MA_AES_CBC:
      if (iv_len != ctx->cipher.c->block_size)
      {
        rc= MA_CRYPTO_EINVIV;
        goto fail;
      }
    default:
      if (flags & MA_CRYPTO_ENCRYPT)
        ctx->cipher.c->set_encrypt_key(ctx->ctx, key);
      else
        ctx->cipher.c->set_decrypt_key(ctx->ctx, key);
      break;
  }
#elif defined(HAVE_CRYPTO_OPENSSL)
  assert(EVP_CIPHER_CTX_key_length(ctx->ctx) == (int)key_len);
  if (flags & MA_CRYPTO_NOPAD)
    EVP_CIPHER_CTX_set_padding(ctx->ctx, 0);
  if (mode == MA_AES_GCM)
  {
    int unused;
    unsigned int real_ivlen= EVP_CIPHER_CTX_iv_length(ctx->ctx);
    if (iv_len > real_ivlen && !EVP_CipherUpdate(ctx->ctx, NULL, &unused,
          iv + real_ivlen,
          iv_len - real_ivlen))
      return MA_CRYPTO_EBADDATA;
  }
#elif defined(HAVE_CRYPTO_BCRYPT)
#endif  
  /* save mode and flags */
  ctx->mode= mode;
  ctx->key= key;
  ctx->key_len= key_len;
  ctx->flags= flags;
  ctx->iv= iv;
  ctx->iv_len= iv_len;
  return 0;
fail:
  return 1;
}
/* }}} */

#ifdef HAVE_CRYPTO_BCRYPT
#include <malloc.h>
/* BCRYPT helper functions for crt block cipher operation

   bcrypt doesn't support CRT block cipher mode, so the following
   code will be used as a workaround:

   Fill the destination buffer with counters, then encrypt the destination
   buffer in ecb mode and xor values with source buffer.
*/

/* this function will fail if size= 0 */
static inline void ctr_increment(size, ctr)
{
  do {
    unsigned increment_i = (size) - 1;
    if (++(ctr)[increment_i] == 0)
      while (increment_i > 0 &&
	     && ++(ctr)[--increment_i] == 0 );
  } while (0)
}
static inline void ctr_xor_mem(unsigned char *dst, 
                        unsigned char *src,
                        unsigned int size)
{
  unsigned i;
  for (i=0; i < size; i++)
    dst[i] ^= src[i];
}

static void ctr_crypt(struct st_crypto_crypt_ctx *ctx, unsigned char *src, unsigned char *dst, unsigned int len)
{
  unsigned int dlen;
  NTSTATUS status;
  status = BCryptEncrypt(ctx->KeyHdl, src, len,
    NULL, NULL, 0, dst, len, &dlen, 0);
  assert(status >= 0);
  assert(len = dlen);
}

static void bcrypt_ctr_crypt(struct st_crypto_crypt_ctx *ctx,
  unsigned char *src,
  unsigned int slen,
  unsigned char *dst,
  unsigned char *ctr)
{
  if (slen == AES_BLOCK_SIZE)
  {
    ctr_crypt(ctx, ctr, dst, AES_BLOCK_SIZE);
    ctr_increment(AES_BLOCK_SIZE, ctr);
    ctr_xor_mem(dst, src, AES_BLOCK_SIZE);
  }
  else
  {
    size_t left;
    int i;
    unsigned char *p;

    /* We don't encrypt block by block. Instead we fill
       the entire buffer with incremented counters and
       encrypt at once in ECB mode */
    for (p = dst, left = slen; 
         left >= AES_BLOCK_SIZE;
         left -= AES_BLOCK_SIZE, p += AES_BLOCK_SIZE)
    {
      memcpy(p, ctr, AES_BLOCK_SIZE);
      ctr_increment(AES_BLOCK_SIZE, ctr);
    }

    if (left < slen)
    {
      ctr_crypt(ctx, dst, dst, slen - left);
      ctr_xor_mem(dst, src, slen - left);
    }

    if (left)
    {
      unsigned char buffer[AES_BLOCK_SIZE];
      int i;
      memcpy(buffer, ctr, AES_BLOCK_SIZE);
      ctr_crypt(ctx, buffer, buffer, AES_BLOCK_SIZE);
      ctr_increment(AES_BLOCK_SIZE, ctr);
      for (i = 0; i < left; i++)
        dst[slen - left + i] = src[slen - left + i] ^ buffer[i];
    }
  }
}
#endif

/* {{{ ma_crypto_update */
int ma_crypto_crypt_update(MA_CRYPTO_CRYPT_CTX cctx,
    const unsigned char *src,
    unsigned int slen,
    unsigned char *dst,
    unsigned int *dlen)
{
  struct st_crypto_crypt_ctx *ctx= (struct st_crypto_crypt_ctx *)cctx;
#ifndef HAVE_CRYPTO_NETTLE
  unsigned int total= 0;
#endif  
  int rc= MA_CRYPTO_OK;

  if (!ctx)
    return MA_CRYPTO_EINVCTX;
  *dlen= 0;

#ifdef HAVE_CRYPTO_NETTLE
  switch(ctx->mode) {
    case MA_AES_ECB:
    case MA_AES_CBC:
      if (ctx->flags & MA_CRYPTO_NOPAD)
      {
        if (slen % AES_BLOCK_SIZE)
          *dlen= ma_crypto_internal_pad(ctx, (unsigned char *)src, dst, &slen);
        if (slen < AES_BLOCK_SIZE)
          return rc;
      }
      else if (ctx->flags & MA_CRYPTO_ENCRYPT)
        ma_crypto_nettle_pkcs7_pad((unsigned char *)src, &slen, AES_BLOCK_SIZE, 1);
      if (ctx->mode == MA_AES_ECB)
      {
        if (ctx->flags & MA_CRYPTO_ENCRYPT)
          ctx->cipher.c->encrypt(ctx->ctx, slen, dst, src);
        else
          ctx->cipher.c->decrypt(ctx->ctx, slen, dst, src);
      } else {
        unsigned char *iiv;
        if (!(iiv= alloca(ctx->cipher.c->block_size)))
          return MA_CRYPTO_ENOMEM;
        /* this is safe, we already checked iv_len during init */
        memcpy(iiv, ctx->iv, ctx->cipher.c->block_size);
        if (ctx->flags & MA_CRYPTO_ENCRYPT)
          cbc_encrypt(ctx->ctx, ctx->cipher.c->encrypt, ctx->cipher.c->block_size,
              iiv, slen, dst, src);
        else
          cbc_decrypt(ctx->ctx, ctx->cipher.c->decrypt, ctx->cipher.c->block_size,
              iiv, slen, dst, src);

      }
      break;
    case MA_AES_GCM:
      if (ctx->flags & MA_CRYPTO_ENCRYPT)
        ctx->cipher.a->encrypt(ctx->ctx, slen, dst, src);
      else
        ctx->cipher.a->decrypt(ctx->ctx, slen, dst, src);
      break;
    case MA_AES_CTR:
      {
        /* prevent reuse of modified iv */
        unsigned char *ctr= alloca(ctx->cipher.c->block_size);
        memcpy(ctr, ctx->iv, ctx->cipher.c->block_size);
        ctr_crypt(ctx->ctx, ctx->cipher.c->encrypt, ctx->cipher.c->block_size,
            ctr, slen, dst, src);
        break;    
      }
  }
  if (!rc)
    *dlen+= slen;
  ctx->src_len= slen;
#elif defined(HAVE_CRYPTO_OPENSSL)
  {
    *dlen= 0;
    if (ctx->mode == MA_AES_GCM)
    {
      if (ctx->flags & MA_CRYPTO_DECRYPT)
      {
        slen-= AES_BLOCK_SIZE;
        if(!EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_SET_TAG, AES_BLOCK_SIZE,
              (void*)(src + slen)))
          return MA_CRYPTO_EBADDATA;
      }
    }
#endif
#if defined(HAVE_CRYPTO_OPENSSL) || defined(HAVE_CRYPTO_BCRYPT)
    if (ctx->flags & MA_CRYPTO_NOPAD)
    {
      if (slen % AES_BLOCK_SIZE)
        *dlen= ma_crypto_internal_pad(ctx, (unsigned char *)src, dst, &slen);
      if (slen < AES_BLOCK_SIZE)
        return rc;
    }
    total= *dlen;
    *dlen= 0;
#if defined(HAVE_CRYPTO_OPENSSL)
    if (!EVP_CipherUpdate(ctx->ctx, dst, (int*)dlen, src, slen))
      return MA_CRYPTO_EBADDATA;
  }
#endif
#ifdef HAVE_CRYPTO_BCRYPT
  {
    NTSTATUS status= 0;
    DWORD pad= (ctx->flags & MA_CRYPTO_NOPAD) ? 0 : BCRYPT_BLOCK_PADDING;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *pauth= NULL;
    PUCHAR pIv= ctx->pIv;
    ULONG ivLen= ctx->iv_len;

    if (ctx->mode == MA_AES_GCM)
    {
      pauth= &ctx->authinfo;
      pIv= 0;
      ivLen= 0;
      pad= 0;
      if (ctx->flags & MA_CRYPTO_DECRYPT)
      {
        pauth->pbTag= src + slen - AES_BLOCK_SIZE;
        slen-= AES_BLOCK_SIZE;
      }
      else
      {
        pauth->pbTag= dst + slen;
      }
    }
    /* since it's not supported, we need to emulate CTR */
    if (ctx->mode == MA_AES_CTR)
    {
      bcrypt_ctr_crypt(ctx, src, slen, dst, pIv);
      *dlen = slen;
      return MA_CRYPTO_OK;
    }

    if (ctx->flags & MA_CRYPTO_ENCRYPT)
      status= BCryptEncrypt(ctx->KeyHdl, src, (ULONG)slen, pauth, pIv, ivLen, 
          dst, slen + AES_BLOCK_SIZE, dlen, pad);
    else
      status= BCryptDecrypt(ctx->KeyHdl, src, slen, pauth, pIv, ivLen,
          dst, slen, dlen, pad);
    if (status < 0)
      return MA_CRYPTO_EBADDATA;
  }
#endif
  *dlen+= total;
#endif

  return rc;
}
/* }}} */

/* {{{ ma_crypto_finish */
int ma_crypto_crypt_finish(MA_CRYPTO_CRYPT_CTX cctx,
    unsigned char *dst,
    unsigned int *dlen)
{
  struct st_crypto_crypt_ctx *ctx= (struct st_crypto_crypt_ctx *)cctx;
  int rc= MA_CRYPTO_OK;

  if (!ctx)
    return MA_CRYPTO_EINVCTX;

  *dlen= 0;
#ifdef HAVE_CRYPTO_NETTLE
  switch (ctx->mode) {
    case MA_AES_ECB:
    case MA_AES_CBC:
      /* check if we need to remove padding at decryption */
      if ((ctx->flags & MA_CRYPTO_DECRYPT) &&
          (!(ctx->flags & MA_CRYPTO_NOPAD)) &&
          ctx->src_len >= AES_BLOCK_SIZE)
        ma_crypto_nettle_pkcs7_pad(dst, dlen, AES_BLOCK_SIZE, 0);
      break;
    case MA_AES_GCM:
      ctx->cipher.a->digest(ctx->ctx, ctx->cipher.a->block_size, dst);
      *dlen= (ctx->flags & MA_CRYPTO_ENCRYPT) ? ctx->cipher.a->block_size :
        -ctx->cipher.a->block_size;
      break;
    default:
      break;
  }
#elif defined(HAVE_CRYPTO_OPENSSL)
  if (!(ctx->flags & MA_CRYPTO_NOPAD))
  {
    if (ctx->mode == MA_AES_GCM)
    {
      int fin;
      if (!EVP_CipherFinal_ex(ctx->ctx, dst, &fin))
        return MA_CRYPTO_EBADDATA;
      if (ctx->flags & MA_CRYPTO_ENCRYPT)
      {
        if(!EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_GET_TAG, AES_BLOCK_SIZE, dst))
          return MA_CRYPTO_EBADDATA;
        *dlen= AES_BLOCK_SIZE;
      }
    } else {
      if (!EVP_CipherFinal_ex(ctx->ctx, dst, (int*)dlen))
        return 0;
    }
  }
#elif defined(HAVE_CRYPTO_BCRYPT)
  if (ctx->mode == MA_AES_GCM  &&
      ctx->flags & MA_CRYPTO_ENCRYPT)
    *dlen= AES_BLOCK_SIZE;
#endif
  return rc;
}
/* }}} */

/* {{{ ma_crypto_crypt_deinit */
void ma_crypto_crypt_deinit(MA_CRYPTO_CRYPT_CTX cctx)
{
  struct st_crypto_crypt_ctx *ctx= (struct st_crypto_crypt_ctx *)cctx;
  if (ctx)
  {
#if defined(HAVE_CRYPTO_OPENSSL)
    if (ctx->ctx)
      EVP_CIPHER_CTX_cleanup(ctx->ctx);
    ctx->ctx= NULL;
#elif defined(HAVE_CRYPTO_NETTLE)
    if (ctx->ctx)
      free(ctx->ctx);
    ctx->ctx= NULL;
#elif defined(HAVE_CRYPTO_BCRYPT)
    if (ctx->AlgHdl)
      BCryptCloseAlgorithmProvider(ctx->AlgHdl, 0);
    if (ctx->KeyHdl)
      BCryptDestroyKey(ctx->KeyHdl);
    if (ctx->pIv)
      HeapFree(GetProcessHeap(), 0, ctx->pIv);
    if (ctx->pKey)
      HeapFree(GetProcessHeap(), 0, ctx->pKey);
      ctx->AlgHdl= ctx->KeyHdl= ctx->pIv= ctx->pKey= NULL;
#endif
  }
}
/* }}} */

/* {{{ ma_crypto_crypt_free */
void ma_crypto_crypt_free(MA_CRYPTO_CRYPT_CTX cctx)
{
  struct st_crypto_crypt_ctx *ctx= (struct st_crypto_crypt_ctx *)cctx;
  ma_crypto_crypt_deinit(ctx);
  free(ctx);
}
/* }}} */

/* {{{ ma_crypto_crypt */
int ma_crypto_crypt(enum ma_crypto_aes_mode mode,
                    int flags,
                    const unsigned char *src,
                    unsigned int slen,
                    unsigned char *dst,
                    unsigned int *dlen,
                    const unsigned char *key,
                    unsigned int klen,
                    const unsigned char *iv,
                    unsigned int ivlen)
{
  void *ctx= ma_crypto_crypt_new();
  int res1= 0, res2= 0;
  unsigned int d1= 0, d2= 0;
  if ((res1= ma_crypto_crypt_init(ctx, mode, flags, key, klen, iv, ivlen)))
    return res1;
  res1= ma_crypto_crypt_update(ctx, src, slen, dst, &d1);
  res2= ma_crypto_crypt_finish(ctx, dst + d1, &d2);
  *dlen= d1 + d2;
  ma_crypto_crypt_free(ctx);
  return res1 ? res1 : res2;
}
/* }}} */

/* {{{ ma_crypto_random_bytes */
int ma_crypto_random_bytes(unsigned char* buf, int num)
{
#ifdef HAVE_CRYPTO_NETTLE
  /* Since gnutls uses nettles yarrow implementation,
     we don't need to reimplement complex random calculation
     with nettle functions */
  gnutls_global_init();
  gnutls_rnd(GNUTLS_RND_RANDOM, buf, num);
#elif defined(HAVE_CRYPTO_OPENSSL)
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  RAND_METHOD *rand = RAND_SSLeay();
#else
  RAND_METHOD *rand = RAND_OpenSSL();
#endif
  if (rand == NULL || rand->bytes(buf, num) != 1)
    return MA_CRYPTO_ERND;
#elif defined(HAVE_CRYPTO_BCRYPT)
  if (BCryptGenRandom(NULL, buf, num, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
    return MA_CRYPTO_ERND;
#endif
  return MA_CRYPTO_OK;
}
/* }}} */

unsigned int ma_crypto_crypt_ctx_size(unsigned int unused1 __attribute__((unused)),
                                      unsigned int unused2 __attribute__((unused)))
{
  return (unsigned int)sizeof(struct st_crypto_crypt_ctx);
}
