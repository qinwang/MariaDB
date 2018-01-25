if (!$INNOCHECKSUM) {
  --echo Need innochecksum binary
  --die Need innochecksum binary
}

--disable_warnings
set global innodb_file_format = `Barracuda`;
set global innodb_file_per_table = on;
--enable_warnings

call mtr.add_suppression("InnoDB: Database page corruption on disk or a failed file read of tablespace test/t[0-9]+ page \\[page id: space=[0-9]+, page number=[0-9]+\\]. You may have to recover from a backup.");
call mtr.add_suppression("InnoDB: Page \\[page id: space=[0-9]+, page number= [0-9]+\\] in file ./test/t[0-9]+.ibd may be corrupted. Post compression checksum [0-9]+ stored [0-9]+ compression_method [ZLIB|SNAPPY|LZ4|LZO|LZMA|BZIP2]");
call mtr.add_suppression("InnoDB: Background Page read failed to read or decrypt \\[page id: space=[0-9]+, page number=[0-9]+\\]");
call mtr.add_suppression("mysqld: Index for table 't[0-9]+' is corrupt; try to repair it");

create table t0 (c1 int not null auto_increment primary key, b char(200)) engine=innodb;
create table t1 (c1 int not null auto_increment primary key, b char(200)) engine=innodb page_compressed=1 page_compression_level=1;
create table t2 (c1 int not null auto_increment primary key, b char(200)) engine=innodb page_compressed=1 page_compression_level=2;
create table t3 (c1 int not null auto_increment primary key, b char(200)) engine=innodb page_compressed=1 page_compression_level=3;
create table t4 (c1 int not null auto_increment primary key, b char(200)) engine=innodb page_compressed=1 page_compression_level=4;
create table t5 (c1 int not null auto_increment primary key, b char(200)) engine=innodb page_compressed=1 page_compression_level=5;
create table t6 (c1 int not null auto_increment primary key, b char(200)) engine=innodb page_compressed=1 page_compression_level=6;
create table t7 (c1 int not null auto_increment primary key, b char(200)) engine=innodb page_compressed=1 page_compression_level=7;
create table t8 (c1 int not null auto_increment primary key, b char(200)) engine=innodb page_compressed=1 page_compression_level=8;
create table t9 (c1 int not null auto_increment primary key, b char(200)) engine=innodb page_compressed=1 page_compression_level=9;

--disable_query_log
begin;
let $i = 10;
while ($i)
{
    insert into t0(b) values(REPEAT('Aa',50));
    insert into t0(b) values(REPEAT('a',100));
    insert into t0(b) values(REPEAT('b',100));
    insert into t0(b) values(REPEAT('0',100));
    insert into t0(b) values(REPEAT('1',100));
    dec $i;
}

insert into t1 select * from t0;
insert into t2 select * from t0;
insert into t3 select * from t0;
insert into t4 select * from t0;
insert into t5 select * from t0;
insert into t6 select * from t0;
insert into t7 select * from t0;
insert into t8 select * from t0;
insert into t9 select * from t0;
commit;
--enable_query_log

select count(*) from t1;
select count(*) from t3;
select count(*) from t4;
select count(*) from t5;
select count(*) from t6;
select count(*) from t6;
select count(*) from t7;
select count(*) from t8;
select count(*) from t9;

#
# Wait until pages are really compressed
#
let $wait_condition= select variable_value > 0 from information_schema.global_status where variable_name = 'INNODB_NUM_PAGES_PAGE_COMPRESSED';
--source include/wait_condition.inc

--let $MYSQLD_DATADIR=`select @@datadir`

# shutdown before grep

--source include/shutdown_mysqld.inc

--let t1_IBD = $MYSQLD_DATADIR/test/t0.ibd
--let SEARCH_RANGE = 10000000
--let SEARCH_PATTERN=AaAaAaAa
--echo # t0 expected FOUND
-- let SEARCH_FILE=$t1_IBD
-- source include/search_pattern_in_file.inc
--let t1_IBD = $MYSQLD_DATADIR/test/t1.ibd
--echo # t1 page compressed expected NOT FOUND
-- let SEARCH_FILE=$t1_IBD
-- source include/search_pattern_in_file.inc
--let t1_IBD = $MYSQLD_DATADIR/test/t2.ibd
--echo # t2 page compressed expected NOT FOUND
-- let SEARCH_FILE=$t1_IBD
-- source include/search_pattern_in_file.inc
--let t1_IBD = $MYSQLD_DATADIR/test/t3.ibd
--echo # t3 page compressed expected NOT FOUND
-- let SEARCH_FILE=$t1_IBD
-- source include/search_pattern_in_file.inc
--let t1_IBD = $MYSQLD_DATADIR/test/t4.ibd
--echo # t4 page compressed expected NOT FOUND
-- let SEARCH_FILE=$t1_IBD
-- source include/search_pattern_in_file.inc
--let t1_IBD = $MYSQLD_DATADIR/test/t5.ibd
--echo # t5 page compressed expected NOT FOUND
-- let SEARCH_FILE=$t1_IBD
-- source include/search_pattern_in_file.inc
--let t1_IBD = $MYSQLD_DATADIR/test/t6.ibd
--echo # t6 page compressed expected NOT FOUND
-- let SEARCH_FILE=$t1_IBD
-- source include/search_pattern_in_file.inc
--let t1_IBD = $MYSQLD_DATADIR/test/t7.ibd
--echo # t7 page compressed expected NOT FOUND
-- let SEARCH_FILE=$t1_IBD
-- source include/search_pattern_in_file.inc
--let t1_IBD = $MYSQLD_DATADIR/test/t8.ibd
--echo # t8 page compressed expected NOT FOUND
-- let SEARCH_FILE=$t1_IBD
-- source include/search_pattern_in_file.inc
--let t1_IBD = $MYSQLD_DATADIR/test/t9.ibd
--echo # t9 page compressed expected NOT FOUND
-- let SEARCH_FILE=$t1_IBD
-- source include/search_pattern_in_file.inc

#
# Run innochecksum to all tables, all tables should be ok
#
let t_IBD = $MYSQLD_DATADIR/test/t0.ibd;
--exec $INNOCHECKSUM $t_IBD
let $i=9;
while $($i > 0) {
--echo # Run innochecksum on t$i
let t_IBD = $MYSQLD_DATADIR/test/t$i.ibd;
--exec $INNOCHECKSUM $t_IBD
dec $i;
}

-- source include/start_mysqld.inc

select count(*) from t0;
select count(*) from t1;
select count(*) from t3;
select count(*) from t4;
select count(*) from t5;
select count(*) from t6;
select count(*) from t7;
select count(*) from t8;
select count(*) from t9;

let $wait_condition= select variable_value > 0 from information_schema.global_status where variable_name = 'INNODB_NUM_PAGES_PAGE_DECOMPRESSED';
--source include/wait_condition.inc

let INNODB_PAGE_SIZE=`select @@innodb_page_size`;
let MYSQLD_DATADIR=`select @@datadir`;

--echo # Restart server
--source include/shutdown_mysqld.inc

--echo # Corrupting tablespaces...

#
# Now we corrupt page compressed pages as follows:
# (1) compression method
# (2) payload size
# (3) data
# (4) checksum
#
# Page 0 is not compressed or encrypted
#
perl;
sub ib_write_value {
  my($fh, $file, $pos, $len, $val) = @_;
  seek($fh, $pos, SEEK_SET) or die "$0: seek $file to pos $pos: $!";;
  syswrite($fh, $val, $len) == $len or die "$0: write to $file val $val len $len: $!";;
}
sub ib_corrupt_table {
  my($file, $pos, $val, $len) = @_;
  open(my $fh, "+<", $file) or die "$0: open $file: $!";
  binmode $fh;
  ib_write_value($fh, $file, $pos, $len, $val);
  close $fh or die "$0: close $file: $!";
}
sub ib_read_value {
    my($fh, $file, $pos, $len) = @_;
    seek($fh, $pos, SEEK_SET) or die "$0: seek $file to pos $pos: $!";
    sysread($fh, $buf, $len) == $len or die "$0: read $file : $!";
    return $buf;
}

my($pos) = $ENV{'INNODB_PAGE_SIZE'} * 3;
my($file) = "$ENV{MYSQLD_DATADIR}/test/t1.ibd";
open($fh, "+<", $file) or die "$0: open $file : $!";
binmode $fh;

# Find out the page type, compression method location is based on that
# Note that FIL_HEADER is not encrypted
my($ptype) = unpack("n", ib_read_value($fh, $file, $pos+24, 2));
if ($ptype == 34354) {
   $pos += 32; # FLUSH_LSN_OR_KEY_VERSION + 6
} else {
   $pos += 42; # FIL_PAGE_DATA + 2
}

# Corrupt compression method by decreasing it by one, if zero set 6
# Note that compression method is not encrypted
my($cmethod) = unpack("n", ib_read_value($fh, $file, $pos, 2));
$cmethod--;
if ($cmethod == 0) {
  $cmethod = 6;
}

ib_write_value($fh, $file, $pos, 2, pack("n", $cmethod));
close $fh or die $!;

# (2) corrupt payload size by decreasing size by 50 and if 0 set it to 20
# note that payload size is not encrypted
my($pos) = $ENV{'INNODB_PAGE_SIZE'} * 3 + 40;
my($file) = "$ENV{MYSQLD_DATADIR}/test/t2.ibd";
open($fh, "+<", $file) or die "$0: open $file : $!";
my($size) = unpack("n", ib_read_value($fh, $file, $pos, 2));
$size -= 50;
if ($size <= 0) {
  $size = 20;
}
ib_write_value($fh, $file, $pos, 2, pack("n", $size));
close $fh or die $!;

# (3) Corrupt data

ib_corrupt_table("$ENV{MYSQLD_DATADIR}/test/t3.ibd", $ENV{'INNODB_PAGE_SIZE'} * 3 + 42,
    "deadaaaaffffbbbb",14);

# (4) Corrupt checksum
my($pos) = $ENV{'INNODB_PAGE_SIZE'} * 3;
my($file) = "$ENV{MYSQLD_DATADIR}/test/t4.ibd";
open($fh, "+<", $file) or die "$0: open $file : $!";

# Find out the page type, checksum location is based on that
# Note that FIL_HEADER is not encrypted
my($ptype) = unpack("n", ib_read_value($fh, $file, $pos + 24, 2));
if ($ptype == 37401) {
   $pos += 30;
}
close $fh or die $!;
ib_corrupt_table($file, $pos, pack("n", 0xdead), 2);
EOF

--echo # Corruption done

#
# Run innochecksum to page compressed (and maybe encrypted) tables
# now we should detect corruptions on compressed cases.
# In compressed and  encrypted cases innochecksum can't decrypt
# or decompress so we do not detect all corruptions e.g. corruption on
# compression method.
#
--echo # Run innochecksum on t$i
let t_IBD = $MYSQLD_DATADIR/test/t$i.ibd;
--error 0,1
--exec $INNOCHECKSUM $t_IBD

let $i=4;
while $($i > 1) {
--echo # Run innochecksum on t$i
let t_IBD = $MYSQLD_DATADIR/test/t$i.ibd;
--error 1
--exec $INNOCHECKSUM $t_IBD
dec $i;
}

--echo # Start server again
--source include/start_mysqld.inc

#
# Server should not crash on corrupted tables
#
--error ER_NOT_KEYFILE, ER_GET_ERRMSG
select * from t1;
--error ER_NOT_KEYFILE, ER_GET_ERRMSG
select * from t2;
--error ER_NOT_KEYFILE, ER_GET_ERRMSG
select * from t3;
--error ER_NOT_KEYFILE, ER_GET_ERRMSG
select * from t4;
select count(*) from t5;
select count(*) from t6;
select count(*) from t7;
select count(*) from t8;
select count(*) from t9;

# We should be able to drop even corrupted tables

drop table t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
