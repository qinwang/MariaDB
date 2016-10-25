# Copyright (c) 2012, Oracle and/or its affiliates. All rights reserved.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_SOURCE_DIR}/mysys_ssl
                    ${SSL_INCLUDE_DIRS})

IF(SSL_DEFINES)
ADD_DEFINITIONS(${SSL_DEFINES})
ENDIF()

# this needs to be removed - after viossl support for gnutls and schannel
# was implemented
  IF(WITH_CRYPTO STREQUAL "gnutls")
    pkg_check_modules(GNUTLS REQUIRED gnutls)
    SET(CRYPTO_LIBRARIES ${GNUTLS_LDFLAGS})
    pkg_check_modules(NETTLE REQUIRED nettle)
    SET(CRYPTO_LIBRARIES ${CRYPTO_LIBRARIES} ${NETTLE_LDFLAGS})
    MESSAGE("CRYPTO_LIBRARIES ${CRYPTO_LIBRARIES}")
    ADD_DEFINITIONS(-DHAVE_CRYPTO_GNUTLS)
  ELSEIF(WITH_CRYPTO STREQUAL "bcrypt")
  	ADD_DEFINITIONS(-DHAVE_CRYPTO_BCRYPT)
  ELSE()
    ADD_DEFINITIONS(-DHAVE_CRYPTO_OPENSSL)
  	SET(CRYPTO_LIBRARIES ${SSL_LIBRARIES})
  ENDIF()        

SET(MYSYS_SSL_SOURCES
    my_md5.cc
    my_sha1.cc
    ma_crypto_hash.c
    ma_crypto_crypt.c
   )

ADD_CONVENIENCE_LIBRARY(mysys_ssl ${MYSYS_SSL_SOURCES})
TARGET_LINK_LIBRARIES(mysys_ssl dbug strings ${CRYPTO_LIBRARIES})
DTRACE_INSTRUMENT(mysys_ssl)
