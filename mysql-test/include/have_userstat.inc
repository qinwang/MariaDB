-- require r/have_userstat.require
disable_query_log;
show variables like 'userstat';
enable_query_log;
