# $Id: Password.pm,v 1.4 2001/02/22 00:55:11 btrott Exp $

package Net::SSH::Perl::Auth::Password;

use strict;
use Carp qw/croak/;

use Net::SSH::Perl::Constants qw/SSH_CMSG_AUTH_PASSWORD SSH_SMSG_SUCCESS SSH_SMSG_FAILURE/;

use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Util qw/_read_passphrase/;
use Net::SSH::Perl::Auth;
use base qw/Net::SSH::Perl::Auth/;

sub new {
    my $class = shift;
    my $ssh = shift;
    bless { ssh => $ssh }, $class;
}

sub authenticate {
    my $auth = shift;
    my($packet);

    my $ssh = $auth->{ssh};
    my $pass = $ssh->{pass};
    $ssh->debug("Trying password authentication.");
    if (!$pass) {
        if ($ssh->{interactive}) {
            my $prompt = sprintf "%s@%s's password: ",
                $ssh->{user}, $ssh->{host};
            $pass = _read_passphrase($prompt);
        }
        else {
            $ssh->debug("Will not query passphrase in batch mode.");
        }
    }
    $packet = $ssh->packet_start(SSH_CMSG_AUTH_PASSWORD);
    $packet->put_str($pass);
    $packet->send;

    $packet = Net::SSH::Perl::Packet->read($ssh);
    return 1 if $packet->type == SSH_SMSG_SUCCESS;

    if ($packet->type != SSH_SMSG_FAILURE) {
        croak sprintf "Protocol error: got %d in response to SSH_CMSG_AUTH_PASSWORD",
            $packet->type;
    }

    return 0;
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Auth::Password - Password authentication plugin

=head1 SYNOPSIS

    use Net::SSH::Perl::Auth;
    my $auth = Net::SSH::Perl::Auth->new('Password', $ssh);
    print "Valid auth" if $auth->authenticate;

=head1 DESCRIPTION

I<Net::SSH::Perl::Auth::Password> performs password authentication
with a remote sshd server. When you create a new password auth
object, you give it an I<$ssh> object, which should contain an
open connection to an ssh daemon, as well as the data that the
authentication module needs to proceed.

The I<authenticate> method will enter into a dialog with the
server. For password authentication, all that needs to be done
is to send a password (encrypted by the standard SSH encryption
layer) to the server, and wait for its response. If the I<$ssh>
object doesn't already have a password that you've given it,
I<Net::SSH::Perl::Auth::Password> will check to see if you're
in an interactive session (see the docs for I<Net::SSH::Perl>),
and if so will issue a prompt, asking you to enter your password.
If the session is not interactive (if it's in batch mode), we
send a blank password to comply with the protocol, but odds are
the authentication will then fail.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
