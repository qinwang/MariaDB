/*****************************************************************************

Copyright (c) 1995, 2015, Oracle and/or its affiliates. All Rights Reserved.
Copyright (c) 2017, 2018, MariaDB Corporation.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA

*****************************************************************************/

/**************************************************//**
@file buf/buf0checksum.cc
Buffer pool checksum functions, also linked from /extra/innochecksum.cc

Created Aug 11, 2011 Vasil Dimov
*******************************************************/

#include "univ.i"
#include "fil0fil.h" /* FIL_* */
#include "ut0crc32.h" /* ut_crc32() */
#include "ut0rnd.h" /* ut_fold_binary() */
#include "buf0types.h"
#include "mach0data.h"

#ifndef UNIV_INNOCHECKSUM

#include "srv0srv.h" /* SRV_CHECKSUM_* */

#endif /* !UNIV_INNOCHECKSUM */

/** the macro MYSQL_SYSVAR_ENUM() requires "long unsigned int" and if we
use srv_checksum_algorithm_t here then we get a compiler error:
ha_innodb.cc:12251: error: cannot convert 'srv_checksum_algorithm_t*' to
  'long unsigned int*' in initialization */
UNIV_INTERN ulong	srv_checksum_algorithm = SRV_CHECKSUM_ALGORITHM_INNODB;

/********************************************************************//**
Calculates a page CRC32 which is stored to the page when it is written
to a file. Note that we must be careful to calculate the same value on
32-bit and 64-bit architectures.
@return	checksum */
UNIV_INTERN
ib_uint32_t
buf_calc_page_crc32(
/*================*/
	const byte*	page)	/*!< in: buffer page */
{
	ib_uint32_t	checksum;

	/* Since the field FIL_PAGE_FILE_FLUSH_LSN, and in versions <= 4.1.x
	FIL_PAGE_ARCH_LOG_NO_OR_SPACE_ID, are written outside the buffer pool
	to the first pages of data files, we have to skip them in the page
	checksum calculation.
	We must also skip the field FIL_PAGE_SPACE_OR_CHKSUM where the
	checksum is stored, and also the last 8 bytes of page because
	there we store the old formula checksum. */

	checksum = ut_crc32(page + FIL_PAGE_OFFSET,
			    FIL_PAGE_FILE_FLUSH_LSN_OR_KEY_VERSION
			    - FIL_PAGE_OFFSET)
		^ ut_crc32(page + FIL_PAGE_DATA,
			   UNIV_PAGE_SIZE - FIL_PAGE_DATA
			   - FIL_PAGE_END_LSN_OLD_CHKSUM);

	return(checksum);
}

/********************************************************************//**
Calculates a page checksum which is stored to the page when it is written
to a file. Note that we must be careful to calculate the same value on
32-bit and 64-bit architectures.
@return	checksum */
UNIV_INTERN
ulint
buf_calc_page_new_checksum(
/*=======================*/
	const byte*	page)	/*!< in: buffer page */
{
	ulint checksum;

	/* Since the field FIL_PAGE_FILE_FLUSH_LSN, and in versions <= 4.1.x
	FIL_PAGE_ARCH_LOG_NO_OR_SPACE_ID, are written outside the buffer pool
	to the first pages of data files, we have to skip them in the page
	checksum calculation.
	We must also skip the field FIL_PAGE_SPACE_OR_CHKSUM where the
	checksum is stored, and also the last 8 bytes of page because
	there we store the old formula checksum. */

	checksum = ut_fold_binary(page + FIL_PAGE_OFFSET,
				  FIL_PAGE_FILE_FLUSH_LSN_OR_KEY_VERSION
				  - FIL_PAGE_OFFSET)
		+ ut_fold_binary(page + FIL_PAGE_DATA,
				 UNIV_PAGE_SIZE - FIL_PAGE_DATA
				 - FIL_PAGE_END_LSN_OLD_CHKSUM);
	checksum = checksum & 0xFFFFFFFFUL;

	return(checksum);
}

/********************************************************************//**
In versions < 4.0.14 and < 4.1.1 there was a bug that the checksum only
looked at the first few bytes of the page. This calculates that old
checksum.
NOTE: we must first store the new formula checksum to
FIL_PAGE_SPACE_OR_CHKSUM before calculating and storing this old checksum
because this takes that field as an input!
@return	checksum */
UNIV_INTERN
ulint
buf_calc_page_old_checksum(
/*=======================*/
	const byte*	page)	/*!< in: buffer page */
{
	ulint checksum;

	checksum = ut_fold_binary(page, FIL_PAGE_FILE_FLUSH_LSN_OR_KEY_VERSION);

	checksum = checksum & 0xFFFFFFFFUL;

	return(checksum);
}

/********************************************************************//**
Return a printable string describing the checksum algorithm.
@return	algorithm name */
UNIV_INTERN
const char*
buf_checksum_algorithm_name(
/*========================*/
	srv_checksum_algorithm_t	algo)	/*!< in: algorithm */
{
	switch (algo) {
	case SRV_CHECKSUM_ALGORITHM_CRC32:
		return("crc32");
	case SRV_CHECKSUM_ALGORITHM_STRICT_CRC32:
		return("strict_crc32");
	case SRV_CHECKSUM_ALGORITHM_INNODB:
		return("innodb");
	case SRV_CHECKSUM_ALGORITHM_STRICT_INNODB:
		return("strict_innodb");
	case SRV_CHECKSUM_ALGORITHM_NONE:
		return("none");
	case SRV_CHECKSUM_ALGORITHM_STRICT_NONE:
		return("strict_none");
	}

	ut_error;
	return(NULL);
}

/** Calculates the CRC32 checksum of a page compressed page. The value is
stored to the page when it is written to a file and also checked for
a match when reading from the file. Checksum is calculated from
actual payload of the compressed page and some header fields.

@param[in]	page			buffer page (UNIV_PAGE_SIZE bytes)
@return checksum */
UNIV_INTERN
uint32_t
buf_calc_compressed_crc32(
	const byte*	page)
{
	/* In page compressed pages compression method is stored to field
	FIL_PAGE_FILE_FLUSH_LSN_OR_KEY_VERSION, thus add it to checksum.
	In pages first compressed and then encrypted same field
	contains key version after compression. */

	ulint page_type = mach_read_from_2(page + FIL_PAGE_TYPE);

	ulint header_len =  page_type == FIL_PAGE_PAGE_COMPRESSED ?
		FIL_PAGE_SPACE_ID - FIL_PAGE_OFFSET :
		FIL_PAGE_FILE_FLUSH_LSN_OR_KEY_VERSION - FIL_PAGE_OFFSET;

	const uint32_t	c1 = ut_crc32(
		page + FIL_PAGE_OFFSET,
		header_len);

	/* Calculate checksum from actual payload including stored size
	field. In encrypted case add also compression method field. */
	ulint payload_len = mach_read_from_2(page+FIL_PAGE_DATA)+FIL_PAGE_COMPRESSED_SIZE;

	if (page_type == FIL_PAGE_PAGE_COMPRESSED_ENCRYPTED) {
		payload_len += FIL_PAGE_COMPRESSION_METHOD_SIZE;
	}

	const uint32_t	c2 = ut_crc32(
		page + FIL_PAGE_DATA,
		payload_len);

	return(c1 ^ c2);
}

