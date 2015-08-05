--source include/platform.inc
--vertical_results


# need stable timestamp, because its current value is printed below
set time_zone='+00:00';
set timestamp=unix_timestamp('2014-09-01 13:40:23');
# ditto
set pseudo_thread_id=10;
# to show session != global, and doesn't affect global_value_origin
set sql_mode=ansi_quotes;
# global_value_origin=SQL
set global div_precision_increment=5;

--replace_regex /^\/\S+/PATH/ /^[a-zA-Z]:[\\\/]\S+/PATH/ /^BIGINT\b/<INT or BIGINT>/ /^INT\b/<INT or BIGINT>/ /^(?:18446744073709551615\b|4294967295\b)/<32-bit or 64-bit MAX UNSIGNED>/ /^(?:9223372036854775807\b|2147483647\b)/<32-bit or 64-bit MAX SIGNED>/ /^(?:18446744073709547520\b|4294963200\b)/<32-bit or 64-bit MAX UNSIGNED ADJUSTED>/ /^(?:9223372036853727232\b|2146435072\b)/<32-bit or 64-bit MAX SIGNED ADJUSTED>/
--replace_result $MASTER_MYPORT MASTER_MYPORT

select * from information_schema.system_variables
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

--echo

# now various metadata but no values, for variables where
# values change often

--replace_regex /^BIGINT\b/<INT or BIGINT>/ /^INT\b/<INT or BIGINT>/ /^(?:18446744073709551615\b|4294967295\b)/<32-bit or 64-bit MAX UNSIGNED>/ /^(?:9223372036854775807\b|2147483647\b)/<32-bit or 64-bit MAX SIGNED>/ /^(?:18446744073709547520\b|4294963200\b)/<32-bit or 64-bit MAX UNSIGNED ADJUSTED>/ /^(?:9223372036853727232\b|2146435072\b)/<32-bit or 64-bit MAX SIGNED ADJUSTED>/

select VARIABLE_NAME, VARIABLE_SCOPE, VARIABLE_TYPE, VARIABLE_COMMENT,
       NUMERIC_MIN_VALUE, NUMERIC_MAX_VALUE, NUMERIC_BLOCK_SIZE,
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

--echo

# yet less data: no values, no blocks size, no min/max value.
# row_merge_buff_size is here because of MDEV-8539. See also note about myisam_max_sort_file_size in the report.

--replace_regex /^BIGINT\b/<INT or BIGINT>/ /^INT\b/<INT or BIGINT>/ /^(?:18446744073709551615\b|4294967295\b)/<32-bit or 64-bit MAX UNSIGNED>/ /^(?:9223372036854775807\b|2147483647\b)/<32-bit or 64-bit MAX SIGNED>/ /^(?:18446744073709547520\b|4294963200\b)/<32-bit or 64-bit MAX UNSIGNED ADJUSTED>/ /^(?:9223372036853727232\b|2146435072\b)/<32-bit or 64-bit MAX SIGNED ADJUSTED>/

select VARIABLE_NAME, GLOBAL_VALUE_ORIGIN, VARIABLE_SCOPE, VARIABLE_TYPE,
       VARIABLE_COMMENT, ENUM_VALUE_LIST, READ_ONLY, COMMAND_LINE_ARGUMENT
from information_schema.system_variables
  where variable_name in (
          'log_tc_size',
          'myisam_max_sort_file_size',
          'rowid_merge_buff_size'
        )
  order by variable_name;

set global div_precision_increment=default;
