# $Id: Constants.pm,v 1.3 2001/02/22 01:15:45 btrott Exp $

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
__END__

=head1 NAME

Net::SSH::Perl::Constants - Exportable constants

=head1 SYNOPSIS

    use Net::SSH::Perl::Constants qw( constants );

=head1 DESCRIPTION

I<Net::SSH::Perl::Constants> provides a list of common and
useful constants for use in communicating with an sshd
server, etc.

None of the constants are exported by default; you have to
explicitly ask for them. Some of the constants are grouped
into bundles that you can grab all at once, or you can just
take the individual constants, one by one.

If you wish to import a group, your I<use> statement should
look something like this:

    use Net::SSH::Perl::Constants qw( :group );

Here are the groups:

=over 4

=item * msg

All of the MSG constants. In the SSH packet layer protocol,
each packet is identified by its type; for example, you have
a packet type for starting RSA authentication, a different
type for sending a command, etc. The MSG constants are used
when creating a new packet, then:

    my $packet = $ssh->packet_start( I<msg_constant> );

See the I<Net::SSH::Perl::Packet> and I<Net::SSH::Perl> docs
for details.

I<Net::SSH::Perl> doesn't support all of the features of
the ssh client, so it doesn't need all of its MSG
constants. For a full list of such constants, and an
explanation of each, see the SSH RFC.

Here's the list of MSG constants supported by I<Net::SSH::Perl>:
SSH_MSG_NONE, SSH_MSG_DISCONNECT, SSH_SMSG_PUBLIC_KEY,
SSH_CMSG_SESSION_KEY, SSH_CMSG_USER, SSH_CMSG_AUTH_RHOSTS,
SSH_CMSG_AUTH_RSA, SSH_SMSG_AUTH_RSA_CHALLENGE,
SSH_CMSG_AUTH_RSA_RESPONSE, SSH_CMSG_AUTH_PASSWORD,
SSH_CMSG_EXEC_SHELL, SSH_CMSG_EXEC_CMD, SSH_SMSG_SUCCESS,
SSH_SMSG_FAILURE, SSH_CMSG_STDIN_DATA, SSH_SMSG_STDOUT_DATA,
SSH_SMSG_STDERR_DATA, SSH_CMSG_EOF, SSH_SMSG_EXITSTATUS,
SSH_MSG_IGNORE, SSH_CMSG_EXIT_CONFIRMATION,
SSH_CMSG_AUTH_RHOSTS_RSA, SSH_MSG_DEBUG.

=item * hosts

The HOST constants: HOST_OK, HOST_NEW, and HOST_CHANGED.
These are returned from the C<_check_host_in_hostfile>
routine in I<Net::SSH::Perl::Util>. See that docs for
that routine for an explanation of the meaning of these
constants.

=back

Other exportable constants, not belonging to a group, are:

=over 4

=item * PROTOCOL_MAJOR

=item * PROTOCOL_MINOR

These two constants describe the version of the protocol
supported by this SSH client (ie., I<Net::SSH::Perl>).
They're used when identifying the client to the server
and vice versa.

=item * PRIVATE_KEY_ID_STRING

A special ID string written to private key files; if
the ID string in the file doesn't match this, we stop
reading the private key file.

=item * MAX_PACKET_SIZE

The maximum size of a packet in the packet layer.

=back

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
