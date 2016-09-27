/* Copyright (c) 2012, Oracle and/or its affiliates.
   Copyright (c) 2014, SkySQL Ab.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA */


/**
  @file

  @brief
  Wrapper functions for OpenSSL and YaSSL. Also provides a Compatibility layer
  to make available YaSSL's MD5 implementation.
*/

#include <my_global.h>
#include <my_md5.h>
#include <ma_crypto.h>
#include <stdarg.h>

/**
  Wrapper function to compute MD5 message digest.

  @param digest [out]  Computed MD5 digest
  @param buf    [in]   Message to be computed
  @param len    [in]   Length of the message

  @return              void
*/
void my_md5(uchar *digest, const char *buf, size_t len)
{
  return ma_crypto_hash(MA_CRYPTO_HASH_MD5, digest, (unsigned char *)buf, len);
}


/**
  Wrapper function to compute MD5 message digest for
  two messages in order to emulate md5(msg1, msg2).

  @param digest [out]  Computed MD5 digest
  @param buf1   [in]   First message
  @param len1   [in]   Length of first message
  @param buf2   [in]   Second message
  @param len2   [in]   Length of second message

  @return              void
*/
void my_md5_multi(uchar *digest, ...)
{
  va_list args;
  va_start(args, digest);
  ma_crypto_hash_v(MA_CRYPTO_HASH_MD5, digest, args);
  va_end(args);
}

size_t my_md5_context_size()
{
  return ma_crypto_hash_ctx_size();
}

void my_md5_init(void *context)
{
  ma_crypto_hash_init(context, MA_CRYPTO_HASH_MD5);
}

void my_md5_input(void *context, const uchar *buf, size_t len)
{
  ma_crypto_hash_input(context, buf, len);
}

void my_md5_result(void *context, uchar *digest)
{
  ma_crypto_hash_result(context, digest);
}

void my_md5_deinit(void *context)
{
  ma_crypto_hash_deinit(context);
}
