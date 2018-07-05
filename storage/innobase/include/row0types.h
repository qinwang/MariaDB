/*****************************************************************************

Copyright (c) 1996, 2012, Oracle and/or its affiliates. All Rights Reserved.

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
@file include/row0types.h
Row operation global types

Created 12/27/1996 Heikki Tuuri
*******************************************************/

#ifndef row0types_h
#define row0types_h

struct plan_t;

struct upd_t;
struct upd_field_t;
struct upd_node_t;
struct del_node_t;
struct ins_node_t;
struct sel_node_t;
struct open_node_t;
struct fetch_node_t;

struct row_printf_node_t;
struct sel_buf_t;

struct undo_node_t;

struct purge_node_t;

struct row_ext_t;

/** Buffer for logging modifications during online index creation */
struct row_log_t;

/* MySQL data types */
struct TABLE;

/** Purge virtual column node information. */
struct purge_vcol_info_t {

	/** Used for virtual column computation */
	bool	use_vcol;

	/** True if it is used for the first time. */
        bool	use_first;

	/** MariaDB table opened for virtual column computation. */
	TABLE*	mariadb_table;

	/** constructor to initialize the virtual column info. */
	purge_vcol_info_t() {
		use_first = use_vcol = false;
		mariadb_table = NULL;
	}

	/** Check whether mariadb table exist
	@return true if table exist. */
	bool is_table_exists() const
	{
		return mariadb_table != NULL;
	}

	/** Check whether virtual column information is used
	@return true if virtual column computation happened. */
	bool is_vcol_uses() const
	{
		return use_vcol;
	}

	/** Validate the virtual column information.
	@return true if the mariadb table opened successfully
	or doesn't try to calculate virtual column. */
	bool validate() const
	{
		if (!use_vcol) {
			return true;
		}

		return mariadb_table != NULL;
	}

	/** Set the variable use_vcol and use_first as true if
	it is used for the first time. */
	void set_vcol_use()
	{
		if (use_first) {
			use_first = false;
			ut_ad(use_vcol);
			return;
		}

		use_first = use_vcol = true;
	}

	/** Check whether it fetches mariadb table for the first time.
	@return true if first time tries to open mariadb table. */
	bool is_first_fetch() const
	{
		return use_first;
	}
};

#endif
