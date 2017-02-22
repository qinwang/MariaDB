SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_HANDLERSOCKET")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_HANDLERSOCKET")

IF(HAVE_WVLA)
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wno-vla")
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wno-vla")
ENDIF()

SET(SPIDER_SOURCES
  spd_param.cc spd_sys_table.cc spd_trx.cc spd_db_conn.cc spd_conn.cc
  spd_table.cc spd_direct_sql.cc spd_udf.cc spd_ping_table.cc
  spd_copy_tables.cc spd_i_s.cc spd_malloc.cc ha_spider.cc spd_udf.def
  spd_db_mysql.cc spd_db_handlersocket.cc
  hs_client/config.cpp hs_client/escape.cpp hs_client/fatal.cpp
  hs_client/hstcpcli.cpp hs_client/socket.cpp hs_client/string_util.cpp
)

IF(EXISTS ${PROJECT_SOURCE_DIR}/storage/mysql_storage_engine.cmake)
  SET(CMAKE_CXX_FLAGS_DEBUG 
    "${CMAKE_CXX_FLAGS_DEBUG} -DSAFEMALLOC -DSAFE_MUTEX -DUSE_SYMDIR /Zi")
  SET(CMAKE_C_FLAGS_DEBUG 
    "${CMAKE_C_FLAGS_DEBUG} -DSAFEMALLOC -DSAFE_MUTEX -DUSE_SYMDIR /Zi")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /MAP /MAPINFO:EXPORTS") 
  INCLUDE("${PROJECT_SOURCE_DIR}/storage/mysql_storage_engine.cmake")

  INCLUDE_DIRECTORIES(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/sql
    ${CMAKE_SOURCE_DIR}/regex)

  MYSQL_STORAGE_ENGINE(SPIDER)
ELSE()
  INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/storage/spider/hs_client)

  INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/storage/spider/scripts/install_spider.sql
    DESTINATION ${INSTALL_MYSQLSHAREDIR} COMPONENT Server
  )
  SET(SPIDER_DEB_FILES "usr/lib/mysql/plugin/ha_spider.so usr/share/mysql/install_spider.sql" PARENT_SCOPE)
  MYSQL_ADD_PLUGIN(spider ${SPIDER_SOURCES} STORAGE_ENGINE MODULE_ONLY MODULE_OUTPUT_NAME "ha_spider")
ENDIF()
