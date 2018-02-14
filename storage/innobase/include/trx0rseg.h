/*****************************************************************************

Copyright (c) 1996, 2016, Oracle and/or its affiliates. All Rights Reserved.
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
@file include/trx0rseg.h
Rollback segment

Created 3/26/1996 Heikki Tuuri
*******************************************************/

#ifndef trx0rseg_h
#define trx0rseg_h

#include "trx0types.h"
#include "trx0sys.h"
#include "fut0lst.h"
#include <vector>
#ifdef WITH_WSREP
#include "trx0xa.h"
#endif /* WITH_WSREP */

/** Gets a rollback segment header.
@param[in]	space		space where placed
@param[in]	page_no		page number of the header
@param[in,out]	mtr		mini-transaction
@return rollback segment header, page x-latched */
UNIV_INLINE
trx_rsegf_t*
trx_rsegf_get(
	ulint			space,
	ulint			page_no,
	mtr_t*			mtr);

/** Gets a newly created rollback segment header.
@param[in]	space		space where placed
@param[in]	page_no		page number of the header
@param[in,out]	mtr		mini-transaction
@return rollback segment header, page x-latched */
UNIV_INLINE
trx_rsegf_t*
trx_rsegf_get_new(
	ulint			space,
	ulint			page_no,
	mtr_t*			mtr);

/***************************************************************//**
Sets the file page number of the nth undo log slot. */
UNIV_INLINE
void
trx_rsegf_set_nth_undo(
/*===================*/
	trx_rsegf_t*	rsegf,	/*!< in: rollback segment header */
	ulint		n,	/*!< in: index of slot */
	ulint		page_no,/*!< in: page number of the undo log segment */
	mtr_t*		mtr);	/*!< in: mtr */
/****************************************************************//**
Looks for a free slot for an undo log segment.
@return slot index or ULINT_UNDEFINED if not found */
UNIV_INLINE
ulint
trx_rsegf_undo_find_free(const trx_rsegf_t* rsegf);

/** Creates a rollback segment header.
This function is called only when a new rollback segment is created in
the database.
@param[in]	space		space id
@param[in]	rseg_id		rollback segment identifier
@param[in,out]	sys_header	the TRX_SYS page (NULL for temporary rseg)
@param[in,out]	mtr		mini-transaction
@return page number of the created segment, FIL_NULL if fail */
ulint
trx_rseg_header_create(
	ulint			space,
	ulint			rseg_id,
	buf_block_t*		sys_header,
	mtr_t*			mtr);

/** Initialize the rollback segments in memory at database startup. */
void
trx_rseg_array_init();

/** Free a rollback segment in memory. */
void
trx_rseg_mem_free(trx_rseg_t* rseg);

/** Create a persistent rollback segment.
@param[in]	space_id	system or undo tablespace id
@return pointer to new rollback segment
@retval	NULL	on failure */
trx_rseg_t*
trx_rseg_create(ulint space_id)
	MY_ATTRIBUTE((warn_unused_result));

/** Create the temporary rollback segments. */
void
trx_temp_rseg_create();

/********************************************************************
Get the number of unique rollback tablespaces in use except space id 0.
The last space id will be the sentinel value ULINT_UNDEFINED. The array
will be sorted on space id. Note: space_ids should have have space for
TRX_SYS_N_RSEGS + 1 elements.
@return number of unique rollback tablespaces in use. */
ulint
trx_rseg_get_n_undo_tablespaces(
/*============================*/
	ulint*		space_ids);	/*!< out: array of space ids of
					UNDO tablespaces */
/* Number of undo log slots in a rollback segment file copy */
#define TRX_RSEG_N_SLOTS	(UNIV_PAGE_SIZE / 16)

/* Maximum number of transactions supported by a single rollback segment */
#define TRX_RSEG_MAX_N_TRXS	(TRX_RSEG_N_SLOTS / 2)

/** The rollback segment memory object */
struct trx_rseg_t {
	/*--------------------------------------------------------*/
	/** rollback segment id == the index of its slot in the trx
	system file copy */
	ulint				id;

	/** mutex protecting the fields in this struct except id,space,page_no
	which are constant */
	RsegMutex			mutex;

	/** space where the rollback segment header is placed */
	ulint				space;

	/** page number of the rollback segment header */
	ulint				page_no;

	/** current size in pages */
	ulint				curr_size;

	/*--------------------------------------------------------*/
	/* Fields for undo logs */
	/** List of undo logs */
	UT_LIST_BASE_NODE_T(trx_undo_t)	undo_list;

	/** List of undo log segments cached for fast reuse */
	UT_LIST_BASE_NODE_T(trx_undo_t)	undo_cached;

	/** List of recovered old insert_undo logs of incomplete
	transactions (to roll back or XA COMMIT & purge) */
	UT_LIST_BASE_NODE_T(trx_undo_t) old_insert_list;

	/*--------------------------------------------------------*/

	/** Page number of the last not yet purged log header in the history
	list; FIL_NULL if all list purged */
	ulint				last_page_no;

	/** Byte offset of the last not yet purged log header */
	ulint				last_offset;

	/** Transaction number of the last not yet purged log */
	trx_id_t			last_trx_no;

	/** Whether the log segment needs purge */
	bool				needs_purge;

	/** Reference counter to track rseg allocated transactions. */
	ulint				trx_ref_count;

	/** If true, then skip allocating this rseg as it reside in
	UNDO-tablespace marked for truncate. */
	bool				skip_allocation;

	/** @return whether the rollback segment is persistent */
	bool is_persistent() const
	{
		ut_ad(space == SRV_TMP_SPACE_ID
		      || space == TRX_SYS_SPACE
		      || (srv_undo_space_id_start > 0
			  && space >= srv_undo_space_id_start
			  && space <= srv_undo_space_id_start
			  + TRX_SYS_MAX_UNDO_SPACES));
		ut_ad(space == SRV_TMP_SPACE_ID
		      || space == TRX_SYS_SPACE
		      || (srv_undo_space_id_start > 0
			  && space >= srv_undo_space_id_start
			  && space <= srv_undo_space_id_start
			  + srv_undo_tablespaces_active)
		      || !srv_was_started);
		return(space != SRV_TMP_SPACE_ID);
	}
};

/* Undo log segment slot in a rollback segment header */
/*-------------------------------------------------------------*/
#define	TRX_RSEG_SLOT_PAGE_NO	0	/* Page number of the header page of
					an undo log segment */
/*-------------------------------------------------------------*/
/* Slot size */
#define TRX_RSEG_SLOT_SIZE	4

/* The offset of the rollback segment header on its page */
#define	TRX_RSEG		FSEG_PAGE_DATA

/* Transaction rollback segment header */
/*-------------------------------------------------------------*/
/** 0xfffffffe = pre-MariaDB 10.3.5 format; 0=MariaDB 10.3.5 or later */
#define	TRX_RSEG_FORMAT		0
/** Number of pages in the TRX_RSEG_HISTORY list */
#define	TRX_RSEG_HISTORY_SIZE	4
/** Committed transaction logs that have not been purged yet */
#define	TRX_RSEG_HISTORY	8
#define	TRX_RSEG_FSEG_HEADER	(8 + FLST_BASE_NODE_SIZE)
					/* Header for the file segment where
					this page is placed */
#define TRX_RSEG_UNDO_SLOTS	(8 + FLST_BASE_NODE_SIZE + FSEG_HEADER_SIZE)
					/* Undo log segment slots */
/** Maximum transaction ID (valid only if TRX_RSEG_FORMAT is 0) */
#define TRX_RSEG_MAX_TRX_ID	(TRX_RSEG_UNDO_SLOTS + TRX_RSEG_N_SLOTS	\
				 * TRX_RSEG_SLOT_SIZE)

/** Maximum length of MySQL binlog file name, in bytes. */
#define TRX_RSEG_BINLOG_NAME_LEN	512
/** Contents of TRX_RSEG_MYSQL_LOG_MAGIC_N_FLD */
#define TRX_RSEG_BINLOG_MAGIC_N		873422344

/* The offset of the MySQL commit info in the rollback segment header. */
#define TRX_RSEG_COMMIT_INFO	TRX_RSEG_MAX_TRX_ID + 8

/** Sequence to find latest binlog information IN RSEG HEADER. */
#define TRX_RSEG_COMMIT_ID	0

/** Magic number which is TRX_RSEG_BINLOG_MAGIC_N if we have valid data
in the MYSQL binlog info. */
#define TRX_RSEG_BINLOG_MAGIC_N_FLD	8

/** 8 bytes offset within that file */
#define TRX_RSEG_BINLOG_OFFSET		12

/** MySQL log file name */
#define TRX_RSEG_BINLOG_NAME		20

#ifdef WITH_WSREP
/** The offset to WSREP XID headers */
#define	TRX_RSEG_WSREP_XID_INFO	(TRX_RSEG_COMMIT_INFO \
				 + TRX_RSEG_BINLOG_NAME \
				 + TRX_RSEG_BINLOG_NAME_LEN)

#define TRX_RSEG_WSREP_XID_MAGIC_N_FLD	0
#define TRX_RSEG_WSREP_XID_MAGIC_N	0x77737265

/** XID field: formatID, gtrid_len, bqual_len, xid_data */
#define TRX_RSEG_WSREP_XID_LEN		(4 + 4 + 4 + XIDDATASIZE)
#define TRX_RSEG_WSREP_XID_FORMAT	4
#define TRX_RSEG_WSREP_XID_GTRID_LEN	8
#define TRX_RSEG_WSREP_XID_BQUAL_LEN	12
#define TRX_RSEG_WSREP_XID_DATA		16
#endif /* WITH_WSREP*/

/*-------------------------------------------------------------*/

/** Read the page number of an undo log slot.
@param[in]	rsegf	rollback segment header
@param[in]	n	slot number */
inline
uint32_t
trx_rsegf_get_nth_undo(const trx_rsegf_t* rsegf, ulint n)
{
	ut_ad(n < TRX_RSEG_N_SLOTS);
	return mach_read_from_4(rsegf + TRX_RSEG_UNDO_SLOTS
				+ n * TRX_RSEG_SLOT_SIZE);
}

#ifdef WITH_WSREP

/** Update the WSREP XID information in rollback segment header.
@param[in]	rseg_header	rollback segment header
@param[in]	xid		Transaction XID
@param[out]	commit_id	commit_id to find the latest commit info
@param[in,out]	mtr		mini-transaction. */
bool
trx_rseg_update_wsrep_checkpoint(
	trx_rsegf_t*	rseg_header,
	const XID*	xid,
	int64_t&	commit_id,
	mtr_t*		mtr);

/** Read the WSREP XID information in rollback segment header.
@param[in]	rseg_header	Rollback segment header
@param[out]	xid		Transaction XID
@param[in]	mtr		mini-transaction. */
void
trx_rseg_read_wsrep_checkpoint(
	trx_rsegf_t*	rseg,
	XID&		xid,
	mtr_t*		mtr);

#endif /* WITH_WSREP */

/** Update the offset information about the end of the MySQL binlog entry
which corresponds to the transaction just being committed. In a MySQL
replication slave updates the master binlog position up to which
replication has proceeded.
@param[in]	trx		transaction
@param[in,out]	commit_id	commit id to identify
				the recent binlog information
@param[in,out]	mtr		mini-transaction */
void
trx_rseg_update_mysql_binlog_offset(
	const trx_t*	trx,
	int64_t&	commit_id,
	mtr_t*		mtr);

/** Read the offset information about the end of MySQL binlog entry
from rollback segment header pages.
@param[in]	rseg_header	rollback segment header
@param[out]	file_name	MySQL log file name
@param[out]	offset		position in that log file
@param[in]	mtr		mini-transaction */
void
trx_rseg_read_mysql_binlog_offset(
	trx_rsegf_t*	rseg_hdr,
	char*		file_name,
	int64_t&	offset,
	mtr_t*		mtr);

/** Structure used to store the binlog and WSREP xid information from
rollback segment header page. */
struct trx_rseg_log_commit_info {

	/** Identifier of the binlog commit information. It is used to
	identify the last commit info. */
	ib_int64_t	id;

#ifdef WITH_WSREP
	/** wsrep_xid. */
	XID		wsrep_xid;
#endif /* WSREP */

	/** Binlog offset stored in RSEG_HEADER */
	int64_t		offset;

	/** Binlog name stored in RSEG_HEADER */
	char		filename[TRX_SYS_MYSQL_LOG_NAME_LEN];

	/** Intialize all the members in the structure. */
	void init() {
		id = 0;

#ifdef WITH_WSREP
		memset(&wsrep_xid, 0, sizeof(wsrep_xid));
		long long seqno= -1;
		memcpy(wsrep_xid.data + 24, &seqno, sizeof(long long));
		wsrep_xid.formatID = -1;
#endif
		offset = -1;
	}
};

#include "trx0rseg.ic"

#endif
