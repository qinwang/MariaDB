# Embedded server does not support crashing
--source include/not_embedded.inc
--source include/have_innodb.inc
--source include/innodb_page_size.inc
--source include/have_debug.inc

call mtr.add_suppression("InnoDB: Failed to set O_DIRECT on file.*");
call mtr.add_suppression("InnoDB: Cannot recover page \\[page id: space=[1-9][0-9]*, page number=[1-9][0-9]*\\] from the doublewrite buffer because it was written in reduced-doublewrite mode");
call mtr.add_suppression("InnoDB: Database page corruption on disk or a failed file read of tablespace .*");
call mtr.add_suppression("InnoDB: Failed to read file .* at offset .*: Page read from tablespace is corrupted.");
call mtr.add_suppression("InnoDB: Table .* is corrupted. Please drop the table and recreate.");

# Slow shutdown and restart to make sure ibuf merge is finished
SET GLOBAL innodb_fast_shutdown = 0;

let INNODB_PAGE_SIZE=`select @@innodb_page_size`;
let MYSQLD_DATADIR=`select @@datadir`;

SET GLOBAL innodb_doublewrite=2;

show variables like 'innodb_doublewrite';
show variables like 'innodb_fil_make_page_dirty_debug';
show variables like 'innodb_saved_page_number_debug';

CREATE TABLE t1(a INT PRIMARY KEY AUTO_INCREMENT, b char(255) default '') ENGINE=innodb;
start transaction;
INSERT INTO t1(b) VALUES(repeat('#',200));
INSERT INTO t1(b) VALUES(repeat('+',200));
INSERT INTO t1(b) VALUES(repeat('/',200));
INSERT INTO t1(b) VALUES(repeat('|',200));
INSERT INTO t1(b) VALUES(repeat('\\',200));
INSERT INTO t1(b) VALUES(repeat('-',200));
INSERT INTO t1(b) VALUES(repeat('&',200));
INSERT INTO t1(b) VALUES(repeat('%',200));
INSERT INTO t1(b) VALUES(repeat('@',200));
INSERT INTO t1(b) VALUES(repeat('?',200));
INSERT INTO t1(b) SELECT b FROM t1;
INSERT INTO t1(b) SELECT b FROM t1;
INSERT INTO t1(b) SELECT b FROM t1;
INSERT INTO t1(b) SELECT b FROM t1;
INSERT INTO t1(b) SELECT b FROM t1;
INSERT INTO t1(b) SELECT b FROM t1;
INSERT INTO t1(b) SELECT b FROM t1;
INSERT INTO t1(b) SELECT b FROM t1;
commit work;

select space from information_schema.innodb_sys_tables where name = 'test/t1' into @space_id;
let SPACE_ID=`select space from information_schema.innodb_sys_tables where name = 'test/t1'`;

--echo # Ensure that dirty pages of table t1 is flushed.
flush tables t1 for export;
unlock tables;

begin;
insert into t1(b) values (repeat('_', 42));

--source ../include/no_checkpoint_start.inc

--echo # Make the first page dirty for table t1
set global innodb_saved_page_number_debug = 0;
set global innodb_fil_make_page_dirty_debug = @space_id;

--echo # Ensure that dirty pages of table t1 are flushed.
set global innodb_buf_flush_list_now = 1;

--let CLEANUP_IF_CHECKPOINT=drop table t1;
--source ../include/no_checkpoint_end.inc

--echo # Backup table and system tablespace before corrupting
--copy_file $MYSQLD_DATADIR/test/t1.ibd $MYSQLD_DATADIR/test/t1.ibd.backup
--copy_file $MYSQLD_DATADIR/ibdata1 $MYSQLD_DATADIR/ibdata1.backup

#
# Corrupt page 5 from table t1 and write page no 5 to first doublewrite
# buffer
#
perl;
use IO::Handle;
use Data::HexDump;
my $fname= "$ENV{'MYSQLD_DATADIR'}test/t1.ibd";
my $page_size = $ENV{INNODB_PAGE_SIZE};
my $tspace_id = $ENV{SPACE_ID};
my $page;

open(FILE, "+<", $fname) or die "Unable to open $fname\n";;
binmode FILE;
sysseek(FILE, 5 * $page_size + 48, 0)||die "Unable to seek $fname\n";
print FILE pack("H*", "deadbeefdeadbeefdeadbeefdeadbeef");
close FILE or die "Unable to close $fname\n";

open(FILE, "+<", "$ENV{MYSQLD_DATADIR}ibdata1")||die "cannot open ibdata1\n";
sysseek(FILE, 6 * $page_size - 190, 0)||die "Unable to seek ibdata1\n";
sysread(FILE, $_, 12) == 12||die "Unable to read TRX_SYS\n";
my($magic,$d1,$d2)=unpack "NNN", $_;
die "magic=$magic, $d1, $d2\n" unless $magic == 536853855 && $d2 >= $d1 + 64;
my($offset)=$d1*$page_size;
# Find and read the page type from first page in the doublewrite buffer
sysseek(FILE, $offset, 0)||die "Unable to seek ibdata1\n";
sysread(FILE, $_, 4096)== 4096||die "Cannot read doublewrite\n";
sysseek(FILE, $offset + 24, 0)||die "Unable to seek ibdata1\n";
sysread(FILE, $_, 2) == 2||die "Unable to read FIL_PAGE_TYPE\n";
my($pagetype)=unpack "n", $_;
die "Not reduced doublewrite page page_type=$pagetype\n" unless $pagetype == 32124;
# Find and read the space_id + page_no from first doublewrite page
sysseek(FILE, $offset + 38, 0)||die "Unable to seek ibdata1\n";
sysread(FILE, $_, 10) == 10||die "Unable to read doublewrite buf\n";
my($first_free,$space_id,$page_no)=unpack ("nNN", $_);
# Write space_id + page_no = 5 to first doublewrite page
sysseek(FILE, $offset, 0)||die "Unable to seek ibdata1\n";
sysread(FILE, $_, $page_size)==$page_size||die "Cannot read doublewrite\n";
sysseek(FILE, $offset, 0)||die "Unable to seek ibdata1\n";
substr ($_, 38, 10) = pack("nNN", 1, $tspace_id, 5);
# Replace the innodb_checksum_algorithm=none checksum
substr ($_, 0, 4) = pack("N", 0xdeadbeef);
substr ($_, $page_size - 8, 4) = pack("N", 0xdeadbeef);
syswrite(FILE, $_, $page_size)==$page_size||die;
close(FILE);
exit 0;
EOF

--enable_reconnect
# Write file to make mysql-test-run.pl start up the server again
--exec echo "restart" > $MYSQLTEST_VARDIR/tmp/mysqld.1.expect
--error 1
--source include/wait_until_connected_again.inc

--error 1932
SELECT * FROM t1;

--source include/shutdown_mysqld.inc

--let SEARCH_RANGE = 10000000
--let SEARCH_FILE= $MYSQLTEST_VARDIR/log/mysqld.1.err
--let SEARCH_PATTERN=buffer because it was written in reduced-doublewrite mode
--replace_regex /FOUND [1-9][0-9]*/ FOUND 1/
--source include/search_pattern_in_file.inc
--let SEARCH_PATTERN=Database page corruption on disk or a failed file read of tables
--replace_regex /FOUND [1-9][0-9]*/ FOUND 1/
--source include/search_pattern_in_file.inc

--echo # Backup table and system tablespace BACK
--move_file $MYSQLD_DATADIR/test/t1.ibd.backup $MYSQLD_DATADIR/test/t1.ibd
--move_file $MYSQLD_DATADIR/ibdata1.backup $MYSQLD_DATADIR/ibdata1

--source include/start_mysqld.inc

CHECK TABLE t1;
SELECT COUNT(*) FROM t1;

SET GLOBAL innodb_doublewrite=1;
CREATE TABLE t2(a INT PRIMARY KEY AUTO_INCREMENT, b char(255) default '') ENGINE=innodb;
start transaction;
INSERT INTO t2(b) VALUES(repeat('#',200));
INSERT INTO t2(b) VALUES(repeat('+',200));
INSERT INTO t2(b) VALUES(repeat('/',200));
INSERT INTO t2(b) VALUES(repeat('|',200));
INSERT INTO t2(b) VALUES(repeat('\\',200));
INSERT INTO t2(b) VALUES(repeat('-',200));
INSERT INTO t2(b) VALUES(repeat('&',200));
INSERT INTO t2(b) VALUES(repeat('%',200));
INSERT INTO t2(b) VALUES(repeat('@',200));
INSERT INTO t2(b) VALUES(repeat('?',200));
INSERT INTO t2(b) SELECT b FROM t2;
INSERT INTO t2(b) SELECT b FROM t2;
INSERT INTO t2(b) SELECT b FROM t2;
INSERT INTO t2(b) SELECT b FROM t2;
INSERT INTO t2(b) SELECT b FROM t2;
INSERT INTO t2(b) SELECT b FROM t2;
INSERT INTO t2(b) SELECT b FROM t2;
INSERT INTO t2(b) SELECT b FROM t2;
commit work;

select space from information_schema.innodb_sys_tables where name = 'test/t2' into @space_id;
let SPACE_ID=`select space from information_schema.innodb_sys_tables where name = 'test/t2'`;

--echo # Ensure that dirty pages of table t2 is flushed.
flush tables t2 for export;
unlock tables;

begin;
insert into t2(b) values (repeat('_', 42));

--source ../include/no_checkpoint_start.inc

--echo # Make the first page dirty for table t2
set global innodb_saved_page_number_debug = 0;
set global innodb_fil_make_page_dirty_debug = @space_id;

--echo # Ensure that dirty pages of table t2 are flushed.
set global innodb_buf_flush_list_now = 1;

--let CLEANUP_IF_CHECKPOINT=drop table t2;
--source ../include/no_checkpoint_end.inc

#
# Write page 5 from t2.ibd to first doublewrite buffer page
# and then corrupt the page 5 from t2.ibd.
#
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}test/t2.ibd";
my $page_size = $ENV{INNODB_PAGE_SIZE};
my $tspace_id = $ENV{SPACE_ID};
my $page;
my $page2;

open(FILE, "+<", "$ENV{MYSQLD_DATADIR}ibdata1")||die "cannot open ibdata1\n";
sysseek(FILE, 6 * $page_size - 190, 0)||die "Unable to seek ibdata1\n";
sysread(FILE, $_, 12) == 12||die "Unable to read TRX_SYS\n";
my($magic,$d1,$d2)=unpack "NNN", $_;
die "magic=$magic, $d1, $d2\n" unless $magic == 536853855 && $d2 >= $d1 + 64;
my($offset)=$d1*$page_size;
# Find and read the page type from first page in the doublewrite buffer
sysseek(FILE, $offset, 0)||die "Unable to seek ibdata1\n";
sysread(FILE, $_, 4096)== 4096||die "Cannot read doublewrite\n";
sysseek(FILE, $offset + 24, 0)||die "Unable to seek ibdata1\n";
sysread(FILE, $_, 2) == 2||die "Unable to read FIL_PAGE_TYPE\n";
my($pagetype)=unpack "n", $_;
die "Not full doublewrite page page_type=$pagetype\n" unless $pagetype != 32124;
sysseek(FILE, $offset, 0)||die "Unable to seek ibdata1\n";
# Read page 5 from t2.ibd
open(FILE2, "+<", $fname) or die "Unable to open $fname\n";;
binmode FILE2;
sysseek(FILE2, 5 * $page_size, 0)||die "Unable to seek $fname\n";
sysread(FILE2, $page2, $page_size)==$page_size||die "Cannot read page from $fname\n";
# Write page 5 from t2.ibd to first doublewrite buffer page
syswrite(FILE, $page2, $page_size)==$page_size||die "Cannot write doublewrite page to ibdata1\n";
close(FILE);
close(FILE2);
# Corrupt page 5 from t2.ibd
open(FILE, "+<", $fname) or die "Unable to open $fname\n";;
binmode FILE;
sysseek(FILE, 5 * $page_size + 50, 0)||die "Unable to seek $fname\n";
print FILE pack("H*", "deadbeefdeadbeefdeadbeefdddddddddddffffffffffffeeeeeeeeeeeebbbbbbbbbbbb");
close(FILE);
exit 0;
EOF

--source include/start_mysqld.inc

CHECK TABLE t1;
CHECK TABLE t2;

SELECT COUNT(*) FROM t1;
SELECT COUNT(*) FROM t2;

DROP TABLE t1;
DROP TABLE t2;

--let SEARCH_RANGE = 10000000
--let SEARCH_FILE= $MYSQLTEST_VARDIR/log/mysqld.1.err
--let SEARCH_PATTERN=Trying to recover page
--replace_regex /FOUND [1-9][0-9]*/ FOUND 1/
--source include/search_pattern_in_file.inc
--let SEARCH_PATTERN=Recovered page
--replace_regex /FOUND [1-9][0-9]*/ FOUND 1/
--source include/search_pattern_in_file.inc
