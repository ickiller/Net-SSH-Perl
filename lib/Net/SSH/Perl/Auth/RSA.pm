# $Id: RSA.pm,v 1.8 2001/02/24 01:39:13 btrott Exp $

package Net::SSH::Perl::Auth::RSA;

use strict;

use Net::SSH::Perl::Constants qw/
    SSH_SMSG_FAILURE
    SSH_SMSG_SUCCESS
    SSH_CMSG_AUTH_RSA
    SSH_SMSG_AUTH_RSA_CHALLENGE
    SSH_CMSG_AUTH_RSA_RESPONSE/;

use Net::SSH::Perl::Util qw/:rsa _load_public_key _load_private_key _read_passphrase/;
use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Auth;
use base qw/Net::SSH::Perl::Auth/;

sub new {
    my $class = shift;
    my $ssh = shift;
    bless { ssh => $ssh }, $class;
}

sub authenticate {
    my $auth = shift;
    my $ssh = $auth->{ssh};

    $ssh->debug("RSA authentication is disabled by the client."), return
        unless $ssh->config->get('auth_rsa');

    my $if = $ssh->config->get('identity_files') || [];
    for my $f (@$if) {
        return 1 if $auth->_authenticate($f);
    }
}

sub _authenticate {
    my($auth, $auth_file) = @_;
    my $ssh = $auth->{ssh};
    my($packet);

    my($public_key, $comment, $private_key);
    eval {
        ($public_key, $comment) = _load_public_key($auth_file);
    };
    $ssh->debug("RSA authentication failed: Can't load public key."),
        return 0 if $@;

    $ssh->debug("Trying RSA authentication with key '$comment'");

    $packet = $ssh->packet_start(SSH_CMSG_AUTH_RSA);
    $packet->put_mp_int($public_key->{n});
    $packet->send;

    $packet = Net::SSH::Perl::Packet->read($ssh);
    my $type = $packet->type;
    if ($type == SSH_SMSG_FAILURE) {
        $ssh->debug("Server refused our key.");
        return 0;
    }

    if ($type != SSH_SMSG_AUTH_RSA_CHALLENGE) {
        $ssh->fatal_disconnect("Protocol error during RSA authentication: $type");
    }

    my $challenge = $packet->get_mp_int;
    $ssh->debug("Received RSA challenge from server.");

    eval {
        $private_key = _load_private_key($auth_file, "");
    };
    if (!$private_key || $@) {
        my $passphrase = "";
        if ($ssh->config->get('interactive')) {
            $passphrase = _read_passphrase("Enter passphrase for RSA key '$comment': ");
        }
        else {
            $ssh->debug("Will not query passphrase for '$comment' in batch mode.");
        }

        eval {
            $private_key = _load_private_key($auth_file, $passphrase);
        };
        if (!$private_key || $@) {
            $ssh->debug("Loading private key failed: $@.");
            $packet = $ssh->packet_start(SSH_CMSG_AUTH_RSA_RESPONSE);
            $packet->put_char(0) for (1..16);
            $packet->send;

            Net::SSH::Perl::Packet->read_expect($ssh, SSH_SMSG_FAILURE);
            return 0;
        }
    }

    _respond_to_rsa_challenge($ssh, $challenge, $private_key);

    $packet = Net::SSH::Perl::Packet->read($ssh);
    $type = $packet->type;
    if ($type == SSH_SMSG_SUCCESS) {
        $ssh->debug("RSA authentication accepted by server.");
        return 1;
    }
    elsif ($type != SSH_SMSG_FAILURE) {
        $ssh->fatal_disconnect("Protocol error waiting RSA auth response: $type");
    }

    $ssh->debug("RSA authentication refused.");
    return 0;
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Auth::RSA - Perform RSA authentication

=head1 SYNOPSIS

    use Net::SSH::Perl::Auth;
    my $auth = Net::SSH::Perl::Auth->new('RSA', $ssh);
    print "Valid auth" if $auth->authenticate;

=head1 DESCRIPTION

I<Net::SSH::Perl::Auth::RSA> performs RSA authentication with
a remote sshd server. When you create a new RSA auth object,
you give it an I<$ssh> object, which should contain an open
connection to an ssh daemon, as well as any data that the
authentication module needs to proceed. In this case, for
example, the I<$ssh> object might contain a list of RSA
identity files (see the docs for I<Net::SSH::Perl>).

The I<authenticate> method tries to load the user's public
and private keys, for each of the files listed as identity
files. If you haven't listed any identity files,
F<$ENV{HOME}/.ssh/identity> is used by default. For each
identity, I<authenticate> enters into a dialog with the sshd
server.

The client sends the public key to the server, then waits for
a challenge. Once this challenge is received, the client must
decrypt the challenge using the private key (loaded from the
identity file). When loading the private key, you may need
to enter a passphrase to decrypt the private key itself; first
I<authenticate> tries to decrypt the key using an empty
passphrase (which requires no user intervention). If this
fails, the client checks to see if it's running in an
interactive session. If so, it queries the user for a
passphrase, which is then used to decrypt the private key. If
the session is non-interactive and the private key cannot
be loaded, the client simply sends a dummy response to the
RSA challenge, to comply with the SSH protocol.

Otherwise, if the private key has been loaded, and the
challenge decrypted, the client sends its response to the
server, then waits for success or failure.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
