/* Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#ifndef included_sha2_h
#define included_sha2_h

#include <my_config.h>
#include <ma_crypto.h>

#    ifdef __cplusplus
extern "C" {
#    endif

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH MA_CRYPTO_SHA512_HASH_SIZE
#endif

#ifndef SHA384_DIGEST_LENGTH
#define SHA384_DIGEST_LENGTH MA_CRYPTO_SHA384_HASH_SIZE
#endif

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH MA_CRYPTO_SHA256_HASH_SIZE
#endif

#ifndef SHA224_DIGEST_LENGTH
#define SHA224_DIGEST_LENGTH MA_CRYPTO_SHA224_HASH_SIZE
#endif

#ifdef HAVE_YASSL

#define SHA224(a,b,c) ma_crypto_hash(MA_CRYPTO_HASH_SHA224,(c),(const char *)(a),(b))
#define SHA256(a,b,c) ma_crypto_hash(MA_CRYPTO_HASH_SHA256,(c),(const char *)(a),(b))
#define SHA384(a,b,c) ma_crypto_hash(MA_CRYPTO_HASH_SHA384,(c),(const char *)(a),(b))
#define SHA512(a,b,c) ma_crypto_hash(MA_CRYPTO_HASH_SHA512,(c),(const char *)(a),(b))

#endif

#    ifdef __cplusplus
}
#    endif

#endif /* included_sha2_h */
