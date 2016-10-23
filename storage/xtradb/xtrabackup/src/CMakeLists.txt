# Copyright (c) 2013 Percona LLC and/or its affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA

OPTION(WITH_XTRABACKUP "Include xtrabackup" ON)
IF(NOT WITH_XTRABACKUP)
  RETURN()
ENDIF()


OPTION(WITH_XTRABACKUP_ARCHIVE "Include xtrabackup streaming features" ON)

IF(WITH_XTRABACKUP_ARCHIVE)
  FIND_PACKAGE(libArchive QUIET)
  IF(LibArchive_FOUND)
    ADD_DEFINITIONS(-DHAVE_EXTRABACKUP_ARCHIVE)
    INCLUDE_DIRECTORIES(LibArchive_INCLUDE_DIRS)
    LINK_LIBRARIES(LibArchive_LIBRARIES)
    SET(DS_ARCHIVE_SOURCE ds_archive.c)
  ENDIF()
ENDIF()




INCLUDE_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/storage/xtradb/include
  ${CMAKE_SOURCE_DIR}/sql
  ${CMAKE_CURRENT_SOURCE_DIR}/quicklz
  #${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  )

ADD_DEFINITIONS(-UMYSQL_SERVER)
########################################################################
# xtrabackup binary
########################################################################


ADD_DEFINITIONS(-DPCRE_STATIC=1)

MYSQL_ADD_EXECUTABLE(xtrabackup
  xtrabackup.cc
  innobackupex.cc
  changed_page_bitmap.cc
  compact.cc
  datasink.c
  ${DS_ARCHIVE_SOURCE}
  ds_buffer.c
  ds_compress.c
  ds_encrypt.c
  ds_local.c
  ds_stdout.c
  ds_tmpfile.c
  ds_xbstream.c
  fil_cur.cc
  quicklz/quicklz.c
  read_filt.cc
  write_filt.cc
  wsrep.cc
  xbcrypt_common.c
  xbcrypt_write.c
  xbstream_write.c
  backup_mysql.cc
  backup_copy.cc
  ${PROJECT_SOURCE_DIR}/libmysql/libmysql.c
  )

SET_TARGET_PROPERTIES(xtrabackup PROPERTIES ENABLE_EXPORTS TRUE)

TARGET_LINK_LIBRARIES(xtrabackup 
  sql
  pcreposix
  )

IF(UNIX)
########################################################################
# innobackupex symlink
########################################################################
ADD_CUSTOM_COMMAND(TARGET xtrabackup
                   COMMAND ${CMAKE_COMMAND} ARGS -E create_symlink
                           xtrabackup innobackupex)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/innobackupex DESTINATION ${INSTALL_BINDIR})
ENDIF(UNIX)

########################################################################
# xbstream binary
########################################################################
MYSQL_ADD_EXECUTABLE(xbstream
  ds_buffer.c
  ds_local.c
  ds_stdout.c
  datasink.c
  xbstream.c
  xbstream_read.c
  xbstream_write.c
  )

SET_TARGET_PROPERTIES(xbstream
        PROPERTIES LINKER_LANGUAGE CXX
        )

TARGET_LINK_LIBRARIES(xbstream
  mysys
)