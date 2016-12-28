package My::Suite::XtraBackup;

@ISA = qw(My::Suite);
use My::Find;
use File::Basename;
use strict;

return "Not run for embedded server" if $::opt_embedded_server;

my $xtrabackup_exe=
::mtr_exe_maybe_exists(
  "$::bindir/extra/xtrabackup$::opt_vs_config/xtrabackup",
  "$::path_client_bindir/xtrabackup");

return "No xtrabackup" if !$xtrabackup_exe;


$ENV{XTRABACKUP}= $xtrabackup_exe;

$ENV{XBSTREAM}= ::mtr_exe_maybe_exists(
      "$::bindir/extra/xtrabackup/$::opt_vs_config/xbstream",
      "$::path_client_bindir/xbstream");

my $tar_version = `tar --version 2>&1`;
$ENV{HAVE_TAR} = $! ? 0: 1;
my $xtrabackup_help=`$xtrabackup_exe --help 2>&1`;
$ENV{HAVE_XTRABACKUP_TAR_SUPPORT} =  (index($xtrabackup_help,"'tar'") == -1) ? 0 : 1;

$ENV{INNOBACKUPEX}= "$xtrabackup_exe --innobackupex";

sub skip_combinations {
  my %skip;
  
  my $t;
  foreach $t ('xb_file_key_management','xb_compressed_encrypted','xb_fulltext_encrypted') {
    $skip{$t.'.test'} = 'Test needs file_key_management plugin'  unless $ENV{FILE_KEY_MANAGEMENT_SO};
  }
  foreach $t ('incremental_encrypted') {
    $skip{$t.'.test'} = 'Test needs example_key_management plugin'  unless $ENV{EXAMPLE_KEY_MANAGEMENT_SO};
  }
  foreach $t ('xb_aws_key_management') {
    $skip{$t.'.test'} = 'Test needs aws_key_management plugin'  unless $ENV{AWS_KEY_MANAGEMENT_SO};
  }
  %skip;
}

sub is_default { 1 }

bless { };

