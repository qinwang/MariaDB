--source include/platform.inc
--vertical_results

# In 32bit vs 64bit builds, some variables can have different type (INT vs BIGINT),
# and/or different max/default values (e.g. 2^32-1 vs 2^64-1 etc.).
# To avoid the trouble with maintaining rdiff files, we'll do the masking here.

let $wordsize_specific_types =
  'AUTO_INCREMENT_INCREMENT',
  'AUTO_INCREMENT_OFFSET',
  'BACK_LOG',
  'BINLOG_COMMIT_WAIT_COUNT',
  'BINLOG_COMMIT_WAIT_USEC',
  'CONNECT_TIMEOUT',
  'DEADLOCK_SEARCH_DEPTH_LONG',
  'DEADLOCK_SEARCH_DEPTH_SHORT',
  'DEADLOCK_TIMEOUT_LONG',
  'DEADLOCK_TIMEOUT_SHORT',
  'DEFAULT_WEEK_FORMAT',
  'DELAYED_INSERT_LIMIT',
  'DELAYED_INSERT_TIMEOUT',
  'DELAYED_QUEUE_SIZE',
  'DIV_PRECISION_INCREMENT',
  'EXPIRE_LOGS_DAYS',
  'EXTRA_MAX_CONNECTIONS',
  'FLUSH_TIME',
  'FT_MAX_WORD_LEN',
  'FT_MIN_WORD_LEN',
  'FT_QUERY_EXPANSION_LIMIT',
  'HISTOGRAM_SIZE',
  'HOST_CACHE_SIZE',
  'INTERACTIVE_TIMEOUT',
  'JOIN_CACHE_LEVEL',
  'LOCK_WAIT_TIMEOUT',
  'LOG_SLOW_RATE_LIMIT',
  'LOG_TC_SIZE',
  'LOG_WARNINGS',
  'MAX_ALLOWED_PACKET',
  'MAX_BINLOG_SIZE',
  'MAX_CONNECTIONS',
  'MAX_CONNECT_ERRORS',
  'MAX_DELAYED_THREADS',
  'MAX_ERROR_COUNT',
  'MAX_INSERT_DELAYED_THREADS',
  'MAX_LENGTH_FOR_SORT_DATA',
  'MAX_LONG_DATA_SIZE',
  'MAX_PREPARED_STMT_COUNT',
  'MAX_SEEKS_FOR_KEY',
  'MAX_SORT_LENGTH',
  'MAX_SP_RECURSION_DEPTH',
  'MAX_TMP_TABLES',
  'MAX_WRITE_LOCK_COUNT',
  'METADATA_LOCKS_CACHE_SIZE',
  'METADATA_LOCKS_HASH_INSTANCES',
  'MIN_EXAMINED_ROW_LIMIT',
  'MRR_BUFFER_SIZE',
  'MULTI_RANGE_COUNT',
  'MYISAM_BLOCK_SIZE',
  'MYISAM_DATA_POINTER_SIZE',
  'MYISAM_REPAIR_THREADS',
  'NET_BUFFER_LENGTH',
  'NET_READ_TIMEOUT',
  'NET_RETRY_COUNT',
  'NET_WRITE_TIMEOUT',
  'OPEN_FILES_LIMIT',
  'OPTIMIZER_PRUNE_LEVEL',
  'OPTIMIZER_SEARCH_DEPTH',
  'OPTIMIZER_SELECTIVITY_SAMPLING_LIMIT',
  'OPTIMIZER_USE_CONDITION_SELECTIVITY',
  'PERFORMANCE_SCHEMA_ACCOUNTS_SIZE',
  'PERFORMANCE_SCHEMA_DIGESTS_SIZE',
  'PERFORMANCE_SCHEMA_EVENTS_STAGES_HISTORY_LONG_SIZE',
  'PERFORMANCE_SCHEMA_EVENTS_STAGES_HISTORY_SIZE',
  'PERFORMANCE_SCHEMA_EVENTS_STATEMENTS_HISTORY_LONG_SIZE',
  'PERFORMANCE_SCHEMA_EVENTS_STATEMENTS_HISTORY_SIZE',
  'PERFORMANCE_SCHEMA_EVENTS_WAITS_HISTORY_LONG_SIZE',
  'PERFORMANCE_SCHEMA_EVENTS_WAITS_HISTORY_SIZE',
  'PERFORMANCE_SCHEMA_HOSTS_SIZE',
  'PERFORMANCE_SCHEMA_MAX_COND_CLASSES',
  'PERFORMANCE_SCHEMA_MAX_COND_INSTANCES',
  'PERFORMANCE_SCHEMA_MAX_FILE_CLASSES',
  'PERFORMANCE_SCHEMA_MAX_FILE_HANDLES',
  'PERFORMANCE_SCHEMA_MAX_FILE_INSTANCES',
  'PERFORMANCE_SCHEMA_MAX_MUTEX_CLASSES',
  'PERFORMANCE_SCHEMA_MAX_MUTEX_INSTANCES',
  'PERFORMANCE_SCHEMA_MAX_RWLOCK_CLASSES',
  'PERFORMANCE_SCHEMA_MAX_RWLOCK_INSTANCES',
  'PERFORMANCE_SCHEMA_MAX_SOCKET_CLASSES',
  'PERFORMANCE_SCHEMA_MAX_SOCKET_INSTANCES',
  'PERFORMANCE_SCHEMA_MAX_STAGE_CLASSES',
  'PERFORMANCE_SCHEMA_MAX_STATEMENT_CLASSES',
  'PERFORMANCE_SCHEMA_MAX_TABLE_HANDLES',
  'PERFORMANCE_SCHEMA_MAX_TABLE_INSTANCES',
  'PERFORMANCE_SCHEMA_MAX_THREAD_CLASSES',
  'PERFORMANCE_SCHEMA_MAX_THREAD_INSTANCES',
  'PERFORMANCE_SCHEMA_SESSION_CONNECT_ATTRS_SIZE',
  'PERFORMANCE_SCHEMA_SETUP_ACTORS_SIZE',
  'PERFORMANCE_SCHEMA_SETUP_OBJECTS_SIZE',
  'PERFORMANCE_SCHEMA_USERS_SIZE',
  'PRELOAD_BUFFER_SIZE',
  'PROFILING_HISTORY_SIZE',
  'PROGRESS_REPORT_TIME',
  'PSEUDO_THREAD_ID',
  'QUERY_ALLOC_BLOCK_SIZE',
  'QUERY_CACHE_LIMIT',
  'QUERY_CACHE_MIN_RES_UNIT',
  'QUERY_PREALLOC_SIZE',
  'RANGE_ALLOC_BLOCK_SIZE',
  'READ_BUFFER_SIZE',
  'READ_RND_BUFFER_SIZE',
  'ROWID_MERGE_BUFF_SIZE',
  'SERVER_ID',
  'SLAVE_DOMAIN_PARALLEL_THREADS',
  'SLAVE_MAX_ALLOWED_PACKET',
  'SLAVE_PARALLEL_MAX_QUEUED',
  'SLAVE_PARALLEL_THREADS',
  'SLAVE_TRANSACTION_RETRIES',
  'SLOW_LAUNCH_TIME',
  'STORED_PROGRAM_CACHE',
  'TABLE_DEFINITION_CACHE',
  'TABLE_OPEN_CACHE',
  'THREAD_CACHE_SIZE',
  'THREAD_CONCURRENCY',
  'TRANSACTION_ALLOC_BLOCK_SIZE',
  'TRANSACTION_PREALLOC_SIZE',
  'WAIT_TIMEOUT'
;

let $wordsize_specific_values = 
  'BINLOG_CACHE_SIZE',
  'BINLOG_COMMIT_WAIT_COUNT',
  'BINLOG_COMMIT_WAIT_USEC',
  'BINLOG_STMT_CACHE_SIZE',
  'BULK_INSERT_BUFFER_SIZE',
  'GROUP_CONCAT_MAX_LEN',
  'JOIN_BUFFER_SIZE',
  'MAX_BINLOG_CACHE_SIZE',
  'MAX_BINLOG_STMT_CACHE_SIZE',
  'MAX_HEAP_TABLE_SIZE',
  'MULTI_RANGE_COUNT',
  'MYISAM_MAX_SORT_FILE_SIZE',
  'MYISAM_MMAP_SIZE',
  'MYISAM_REPAIR_THREADS',
  'MYISAM_SORT_BUFFER_SIZE',
  'PSEUDO_THREAD_ID',
  'QUERY_CACHE_SIZE',
  'RAND_SEED1',
  'RAND_SEED2',
  'ROWID_MERGE_BUFF_SIZE',
  'SORT_BUFFER_SIZE',
  'TMP_TABLE_SIZE'
;

# need stable timestamp, because its current value is printed below
set time_zone='+00:00';
set timestamp=unix_timestamp('2014-09-01 13:40:23');
# ditto
set pseudo_thread_id=10;
# to show session != global, and doesn't affect global_value_origin
set sql_mode=ansi_quotes;
# global_value_origin=SQL
set global div_precision_increment=5;

--replace_regex /^\/\S+/PATH/ /^[a-zA-Z]:[\\\/]\S+/PATH/ /select.*from/select <full field list with substitutions> from/
--replace_result $MASTER_MYPORT MASTER_MYPORT
eval
select
  VARIABLE_NAME,
  SESSION_VALUE,
  if (variable_name in ($wordsize_specific_values),
      case
        when global_value = 18446744073709551615 then '<MAX UNSIGNED>'
        when global_value = 9223372036854775807 then '<MAX SIGNED>'
        when global_value = 18446744073709547520 then '<MAX UNSIGNED ADJUSTED>'
        when global_value = 9223372036853727232 then '<MAX SIGNED ADJUSTED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and global_value = 4294967295 then '<MAX UNSIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and global_value = 2147483647 then '<MAX SIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and global_value = 4294963200 then '<MAX UNSIGNED ADJUSTED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and global_value = 2146435072 then '<MAX SIGNED ADJUSTED>'
        else global_value
      end,
      global_value) as GLOBAL_VALUE,
  GLOBAL_VALUE_ORIGIN,
  if (variable_name in ($wordsize_specific_values),
      case
        when default_value = 18446744073709551615 then '<MAX UNSIGNED>'
        when default_value = 9223372036854775807 then '<MAX SIGNED>'
        when default_value = 18446744073709547520 then '<MAX UNSIGNED ADJUSTED>'
        when default_value = 9223372036853727232 then '<MAX SIGNED ADJUSTED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and default_value = 4294967295 then '<MAX UNSIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and default_value = 2147483647 then '<MAX SIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and default_value = 4294963200 then '<MAX UNSIGNED ADJUSTED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and default_value = 2146435072 then '<MAX SIGNED ADJUSTED>'
        else default_value
      end,
      default_value) as DEFAULT_VALUE,
  VARIABLE_SCOPE,
  if (variable_name in ($wordsize_specific_types),
      case
        when variable_type = 'BIGINT' then '<[BIG]INT>'
        when variable_type = 'BIGINT UNSIGNED' then '<[BIG]INT UNSIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and variable_type = 'INT' then '<[BIG]INT>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and variable_type = 'INT UNSIGNED' then '<[BIG]INT UNSIGNED>'
        else variable_type
      end,
      variable_type) as VARIABLE_TYPE,
  VARIABLE_COMMENT,
  NUMERIC_MIN_VALUE,
  if (variable_name in ($wordsize_specific_values),
      case
        when numeric_max_value = 18446744073709551615 then '<MAX UNSIGNED>'
        when numeric_max_value = 9223372036854775807 then '<MAX SIGNED>'
        when numeric_max_value = 18446744073709547520 then '<MAX UNSIGNED ADJUSTED>'
        when numeric_max_value = 9223372036853727232 then '<MAX SIGNED ADJUSTED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and numeric_max_value = 4294967295 then '<MAX UNSIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and numeric_max_value = 2147483647 then '<MAX SIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and numeric_max_value = 4294963200 then '<MAX UNSIGNED ADJUSTED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and numeric_max_value = 2146435072 then '<MAX SIGNED ADJUSTED>'
        else numeric_max_value
      end,
      numeric_max_value) as NUMERIC_MAX_VALUE,
  NUMERIC_BLOCK_SIZE,
  ENUM_VALUE_LIST,
  READ_ONLY,
  COMMAND_LINE_ARGUMENT
from information_schema.system_variables
  where variable_name not like 'aria%' and
        variable_name not like 'debug%' and
        variable_name not like 'wsrep%' and
        variable_name not in (
          'have_openssl',
          'have_symlink',
          'hostname',
          'large_files_support', 'log_tc_size',
          'lower_case_file_system',
          'lower_case_table_names',
          'myisam_max_sort_file_size',
          'open_files_limit',
          'rand_seed1',
          'rand_seed2',
          'rowid_merge_buff_size',
          'system_time_zone',
          'version_comment',
          'version_compile_machine', 'version_compile_os',
          'version_malloc_library', 'version_ssl_library', 'version'
        )
  order by variable_name;

# now various metadata but no values, for variables where
# values change often

--replace_regex /select.*from/select <partial field list with substitutions> from/
eval 
select
  VARIABLE_NAME, VARIABLE_SCOPE,
  if (variable_name in ($wordsize_specific_types),
      case
        when variable_type = 'BIGINT' then '<[BIG]INT>'
        when variable_type = 'BIGINT UNSIGNED' then '<[BIG]INT UNSIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and variable_type = 'INT' then '<[BIG]INT>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and variable_type = 'INT UNSIGNED' then '<[BIG]INT UNSIGNED>'
        else variable_type
      end,
      variable_type) as VARIABLE_TYPE,
  VARIABLE_COMMENT,
  NUMERIC_MIN_VALUE,
  if (variable_name in ($wordsize_specific_values),
      case
        when numeric_max_value = 18446744073709551615 then '<MAX UNSIGNED>'
        when numeric_max_value = 9223372036854775807 then '<MAX SIGNED>'
        when numeric_max_value = 18446744073709547520 then '<MAX UNSIGNED ADJUSTED>'
        when numeric_max_value = 9223372036853727232 then '<MAX SIGNED ADJUSTED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and numeric_max_value = 4294967295 then '<MAX UNSIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and numeric_max_value = 2147483647 then '<MAX SIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and numeric_max_value = 4294963200 then '<MAX UNSIGNED ADJUSTED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and numeric_max_value = 2146435072 then '<MAX SIGNED ADJUSTED>'
        else numeric_max_value
      end,
      numeric_max_value) as NUMERIC_MAX_VALUE,
  NUMERIC_BLOCK_SIZE,
  ENUM_VALUE_LIST, READ_ONLY, COMMAND_LINE_ARGUMENT
from information_schema.system_variables
  where variable_name in (
          'have_openssl',
          'have_symlink',
          'hostname',
          'large_files_support',
          'lower_case_file_system',
          'lower_case_table_names',
          'open_files_limit',
          'rand_seed1',
          'rand_seed2',
          'system_time_zone',
          'version_comment',
          'version_compile_machine', 'version_compile_os',
          'version_malloc_library', 'version_ssl_library', 'version'
        )
  order by variable_name;

# yet less data: no values, no blocks size, no min/max value.
# row_merge_buff_size is here because of MDEV-8539. See also note about myisam_max_sort_file_size in the report.

--replace_regex /select.*from/select <short field list with substitutions> from/
eval
select VARIABLE_NAME, GLOBAL_VALUE_ORIGIN, VARIABLE_SCOPE,
  if (variable_name in ($wordsize_specific_types),
      case
        when variable_type = 'BIGINT' then '<[BIG]INT>'
        when variable_type = 'BIGINT UNSIGNED' then '<[BIG]INT UNSIGNED>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and variable_type = 'INT' then '<[BIG]INT>'
        when ($MTR_word_size = 32 or $MTR_is_windows) and variable_type = 'INT UNSIGNED' then '<[BIG]INT UNSIGNED>'
        else variable_type
      end,
      variable_type) as VARIABLE_TYPE,
       VARIABLE_COMMENT, ENUM_VALUE_LIST, READ_ONLY, COMMAND_LINE_ARGUMENT
  from information_schema.system_variables
  where variable_name in (
          'log_tc_size',
          'myisam_max_sort_file_size',
          'rowid_merge_buff_size'
        )
  order by variable_name;

set global div_precision_increment=default;
