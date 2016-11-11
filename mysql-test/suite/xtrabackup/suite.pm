package My::Suite::XtraBackup;

@ISA = qw(My::Suite);
use My::Find;
use File::Basename;

return "Not run for embedded server" if $::opt_embedded_server;

sub is_default { 1 }

bless { };

