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

#ifndef MYSQL_SERVICE_ERROR_LOG_INCLUDED
#define MYSQL_SERVICE_ERROR_LOG_INCLUDED

/**
@file include/mysql/service_error_log.h

  Write formatted message to MySQL error log.

  On some platforms, messages also could be duplicated elsewhere
  (e.g windows error log)

  Message format  includes current timestamp and severity 
  - one of [Info],[Warning], or [Message]
*/
#ifdef __cplusplus
extern "C" {
#endif

extern struct error_log_service_st {
  void(*sql_print_error)(const char *fmt, ...);
  void(*sql_print_warning)(const char *fmt, ...);
  void(*sql_print_information)(const char *fmt, ...);
} *error_log_service;

#ifdef MYSQL_DYNAMIC_PLUGIN

#define sql_print_error        error_log_service->sql_print_error
#define sql_print_warning      error_log_service->sql_print_warning
#define sql_print_information  error_log_service->sql_print_information

#else

extern void sql_print_error(const char *format, ...);
extern void sql_print_warning(const char *format, ...);
extern void sql_print_information(const char *format, ...);

#endif

#ifdef __cplusplus
}
#endif

#endif
