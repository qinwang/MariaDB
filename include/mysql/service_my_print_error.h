/* Copyright (c) 2016, MariaDB

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

#ifndef MYSQL_SERVICE_MY_PRINT_ERROR_INCLUDED
#define MYSQL_SERVICE_MY_PRINT_ERROR_INCLUDED

/**
  @file include/mysql/service_my_print_error.h

  This service provides functions for plugins to report
  errors to client (without client, the errors are written to the error log).

*/
#ifdef __cplusplus
extern "C" {
#endif

#define ME_OLDWIN	2	/* Use old window */
#define ME_BELL		4	/* Ring bell then printing message */
#define ME_HOLDTANG	8	/* Don't delete last keys */
#define ME_WAITTOT	16	/* Wait for errtime secs of for a action */
#define ME_WAITTANG	32	/* Wait for a user action  */
#define ME_NOREFRESH	64	/* Write the error message to error log */
#define ME_NOINPUT	128	/* Dont use the input libary */
#define ME_JUST_INFO    1024    /**< not error but just info */
#define ME_JUST_WARNING 2048    /**< not error but just warning */
#define ME_FATALERROR   4096    /* Fatal statement error */


extern struct my_print_error_service_st {
  void(*my_error)(unsigned int nr, unsigned long MyFlags, ...);
  void(*my_printf_error)(unsigned int nr, const char *fmt, unsigned long MyFlags,...);
  void(*my_printv_error)(unsigned int error, const char *format, unsigned long MyFlags, va_list ap);
} *my_print_error_service;

#ifdef MYSQL_DYNAMIC_PLUGIN

#define my_error my_print_error_service->my_error
#define my_printf_error my_print_error_service->my_printf_error
#define my_printv_error(A,B,C,D) my_print_error_service->my_printv_error(A,B,C,D)

#else

extern void my_error(unsigned int nr, unsigned long MyFlags, ...);
extern void my_printf_error(unsigned int my_err, const char *format, unsigned long MyFlags, ...);
extern void my_printv_error(unsigned int error, const char *format, unsigned long MyFlags,va_list ap);
#endif

#ifdef __cplusplus
}
#endif

#endif

