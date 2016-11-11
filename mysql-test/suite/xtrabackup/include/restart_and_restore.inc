let $_server_id= `SELECT @@server_id`;
let $_datadir= `SELECT @@datadir`;
let $_expect_file_name= $MYSQLTEST_VARDIR/tmp/mysqld.$_server_id.expect;
exec echo "wait" > $_expect_file_name;
# shutdown server
shutdown_server;
# xtrabackup move back
force-rmdir $_datadir;
exec $XTRABACKUP --copy-back --datadir=$_datadir --target-dir=$targetdir --parallel=2;
# restart server
exec echo "restart" > $_expect_file_name;
enable_reconnect;
source include/wait_until_connected_again.inc;
disable_reconnect;
