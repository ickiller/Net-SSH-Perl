package Net::SSH::Perl::Constants;
use strict;

use constant PROTOCOL_MAJOR => 1;
use constant PROTOCOL_MINOR => 5;

use constant SSH_MSG_NONE => 0;
use constant SSH_MSG_DISCONNECT => 1;
use constant SSH_SMSG_PUBLIC_KEY => 2;
use constant SSH_CMSG_SESSION_KEY => 3;
use constant SSH_CMSG_USER => 4;
use constant SSH_CMSG_AUTH_RHOSTS => 5;
use constant SSH_CMSG_AUTH_RSA => 6;
use constant SSH_SMSG_AUTH_RSA_CHALLENGE => 7;
use constant SSH_CMSG_AUTH_RSA_RESPONSE => 8;
use constant SSH_CMSG_AUTH_PASSWORD => 9;
use constant SSH_CMSG_REQUEST_PTY => 10;
use constant SSH_CMSG_WINDOW_SIZE => 11;
use constant SSH_CMSG_EXEC_SHELL => 12;
use constant SSH_CMSG_EXEC_CMD => 13;
use constant SSH_SMSG_SUCCESS => 14;
use constant SSH_SMSG_FAILURE => 15;
use constant SSH_CMSG_STDIN_DATA => 16;
use constant SSH_SMSG_STDOUT_DATA => 17;
use constant SSH_SMSG_STDERR_DATA => 18;
use constant SSH_CMSG_EOF => 19;
use constant SSH_SMSG_EXITSTATUS => 20;
use constant SSH_MSG_IGNORE => 32;
use constant SSH_CMSG_EXIT_CONFIRMATION => 33;
use constant SSH_CMSG_AUTH_RHOSTS_RSA => 35;
use constant SSH_MSG_DEBUG => 36;

use constant HOST_OK => 1;
use constant HOST_NEW => 2;
use constant HOST_CHANGED => 3;

use constant PRIVATE_KEY_ID_STRING => "SSH PRIVATE KEY FILE FORMAT 1.1\n";

use constant MAX_PACKET_SIZE => 256000;

use vars qw/@EXPORT_OK %EXPORT_TAGS/;
use Exporter;
use base qw/Exporter/;

BEGIN {
    my %EXPORT_RULES = (
        '^SSH_\w?MSG' => 'msg',
        '^HOST'       => 'hosts',
    );

    no strict 'refs';
    my $class = __PACKAGE__;
    while (my($key, $val) = each %{"${class}::"}) {
        local(*ENTRY) = $val;
        if ($key ne "import" && defined $val && defined *ENTRY{CODE}) {
            push @EXPORT_OK, $key;
            for my $rule (keys %EXPORT_RULES) {
                push @{ $EXPORT_TAGS{ $EXPORT_RULES{$rule} } }, $key
                    if $key =~ /$rule/;
            }
        }
    }
}

1;
