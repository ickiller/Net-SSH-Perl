# $Id: PublicKey.pm,v 1.13 2001/05/08 07:04:59 btrott Exp $

package Net::SSH::Perl::Auth::PublicKey;

use strict;

use Net::SSH::Perl::Constants qw(
    SSH2_MSG_USERAUTH_REQUEST
    SSH_COMPAT_OLD_SESSIONID );

use Net::SSH::Perl::Util qw( _read_passphrase );
use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Key;

use Net::SSH::Perl::Auth;
use base qw( Net::SSH::Perl::Auth );

sub new {
    my $class = shift;
    my $ssh = shift;
    my $auth = bless { ssh => $ssh }, $class;
    $auth->enabled( $ssh->config->get('auth_dsa') );
    $auth;
}

sub enabled {
    my $auth = shift;
    $auth->{enabled} = shift if @_;
    $auth->{enabled};
}

sub authenticate {
    my $auth = shift;
    my $try = shift || 0;
    my $ssh = $auth->{ssh};

    my $if = $ssh->config->get('identity_files') || [];
    for my $f (@$if[$try..$#$if]) {
        return 1 if $auth->_authenticate($f);
    }
}

sub _authenticate {
    my($auth, $auth_file) = @_;
    my $ssh = $auth->{ssh};
    my($packet);

    return unless -e $auth_file;

    my($key);
    $ssh->debug("Trying pubkey authentication with key file '$auth_file'");

    $key = Net::SSH::Perl::Key->read_private_pem($auth_file, '',
        \$ssh->{datafellows});
    if (!$key) {
        my $passphrase = "";
        if ($ssh->config->get('interactive')) {
            $passphrase = _read_passphrase("Enter passphrase for keyfile '$auth_file': ");
        }
        else {
            $ssh->debug("Will not query passphrase for '$auth_file' in batch mode.");
        }

        $key = Net::SSH::Perl::Key->read_private_pem($auth_file,
            $passphrase, \$ssh->{datafellows});
        if (!$key) {
            $ssh->debug("Loading private key failed.");
            return 0;
        }
    }

    my $b = Net::SSH::Perl::Buffer->new;
    if ($ssh->{datafellows} & SSH_COMPAT_OLD_SESSIONID) {
        $b->append($ssh->session_id);
    }
    else {
        $b->put_str($ssh->session_id);
    }
    $b->put_int8(SSH2_MSG_USERAUTH_REQUEST);
    my $skip = $b->length;

    $b->put_str($ssh->config->get('user'));
    $b->put_str("ssh-connection");
    $b->put_str("publickey");
    $b->put_int8(1);
    $b->put_str( $key->ssh_name );
    $b->put_str( $key->as_blob );

    my $sigblob = $key->sign($b->bytes);
    $b->put_str($sigblob);

    ## Get rid of session ID and packet type.
    $b->bytes(0, $skip, '');

    $packet = $ssh->packet_start(SSH2_MSG_USERAUTH_REQUEST);
    $packet->append($b->bytes);
    $packet->send;

    return 1;
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Auth::PublicKey - Perform publickey authentication

=head1 SYNOPSIS

    use Net::SSH::Perl::Auth;
    my $auth = Net::SSH::Perl::Auth->new('PublicKey', $ssh);
    $auth->authenticate;

=head1 DESCRIPTION

I<Net::SSH::Perl::Auth::PublicKey> performs publickey authentication
with a remote sshd server. When you create a new PublicKey auth
object, you give it an I<$ssh> object, which should contain an open
connection to an ssh daemon, as well as any data that the
authentication module needs to proceed. In this case, for
example, the I<$ssh> object might contain a list of
identity files (see the docs for I<Net::SSH::Perl>).

The I<authenticate> method tries to load each of the user's
private key identity files (specified in the I<Net::SSH::Perl>
constructor, or defaulted to I<$ENV{HOME}/.ssh/id_dsa>). For
each identity, I<authenticate> enters into a dialog with the
sshd server.

The client sends a message to the server, giving its public
key, plus a signature of the key and the other data in
the message (session ID, etc.). The signature is generated
using the corresponding private key. The sshd receives the
message and verifies the signature using the client's public
key. If the verification is successful, the authentication
succeeds. Otherwise the authentication fails.

When loading each of the private key files, the client first
tries to load the key using an empty passphrase. If this
fails, the client either prompts the user for a passphrase
(if the session is interactive) or skips the key altogether.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
