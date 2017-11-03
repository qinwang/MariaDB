-- require r/have_thread_statistics.require
disable_query_log;
show variables like 'thread_statistics';
enable_query_log;
