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

#ifndef _ma_crypt_internal_h
#define _ma_crypt_internal_h

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

#if defined(HAVE_CRYPTO_GNUTLS)
#include <nettle/aes.h>
#include <nettle/gcm.h>
#include <nettle/cbc.h>
#include <nettle/ctr.h>
#include <nettle/nettle-meta.h>
#include <nettle/yarrow.h>
#include <nettle/macros.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

typedef const struct nettle_hash *MA_CRYPTO_HASH_TYPE;
struct st_crypto_hash_ctx {
  void *ctx;
  MA_CRYPTO_HASH_TYPE hash;
};

struct st_crypto_crypt_ctx {
  union {
    const struct nettle_aead *a;       /* used by GCM only */
    const struct nettle_cipher *c;
  } cipher;
  void *ctx;                           /* nettle cipher context */
  enum ma_crypto_aes_mode mode;        /* block cipher mode */
  int flags;                           /* encrypt, decrypt, nopad */
  unsigned char src_len;
  const unsigned char *key;
  unsigned int key_len;
  const unsigned char *iv;
  unsigned int iv_len;
  unsigned char is_pad;
  unsigned char pad[AES_BLOCK_SIZE];
};
#elif defined(HAVE_CRYPTO_OPENSSL)
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

struct st_crypto_hash_ctx {
  EVP_MD_CTX *ctx;
};
typedef const EVP_MD *MA_CRYPTO_HASH_TYPE;

struct st_crypto_crypt_ctx {
  EVP_CIPHER_CTX *ctx;
  enum ma_crypto_aes_mode mode;        /* block cipher mode */
  int flags;                           /* encrypt, decrypt, nopad */
  const unsigned char *key;
  unsigned int key_len;
  const unsigned char *iv;
  unsigned int iv_len;
};
#elif defined(HAVE_CRYPTO_BCRYPT)
#include <windows.h>
#include <bcrypt.h>

struct st_crypto_hash_ctx {
  BCRYPT_ALG_HANDLE hAlg;
  BCRYPT_HASH_HANDLE hHash;
  char digest[MA_CRYPTO_MAX_HASH_SIZE];
  DWORD digest_len;
};

extern BCRYPT_ALG_HANDLE MA_BCRYPT_ALG_MD5;
extern BCRYPT_ALG_HANDLE MA_BCRYPT_ALG_SHA1;
extern BCRYPT_ALG_HANDLE MA_BCRYPT_ALG_SHA256;
extern BCRYPT_ALG_HANDLE MA_BCRYPT_ALG_SHA384;
extern BCRYPT_ALG_HANDLE MA_BCRYPT_ALG_SHA512;
extern BCRYPT_ALG_HANDLE MA_BCRYPT_ALG_AES;

typedef BCRYPT_ALG_HANDLE MA_CRYPTO_HASH_TYPE;

#ifndef __attribute__
#define __attribute__(a)
#endif

struct st_crypto_crypt_ctx {
  BCRYPT_ALG_HANDLE AlgHdl;
  BCRYPT_KEY_HANDLE KeyHdl;
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authinfo;
  enum ma_crypto_aes_mode mode;        /* block cipher mode */
  int flags;                           /* encrypt, decrypt, nopad */
  const unsigned char *key;
  unsigned int key_len;
  unsigned char iv[AES_BLOCK_SIZE];
  unsigned int iv_len;
};
#endif

#endif /* _ma_crypt_internal_h */
