package Net::SSH::Perl::Auth::Rhosts_RSA;

use strict;
use Carp qw/croak/;
use Digest::MD5 qw/md5/;

use Net::SSH::Perl::Constants qw/
    SSH_SMSG_FAILURE
    SSH_SMSG_SUCCESS
    SSH_CMSG_AUTH_RHOSTS_RSA
    SSH_SMSG_AUTH_RSA_CHALLENGE
    SSH_CMSG_AUTH_RSA_RESPONSE/;

use Net::SSH::Perl::Util qw/:rsa _load_private_key _mp_linearize/;
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
    my($packet);
    my $ssh = $auth->{ssh};

    $ssh->debug("Trying rhosts or /etc/hosts.equiv with RSA host authentication.");

    my $private_key;
    eval {
        $private_key = _load_private_key("/etc/ssh_host_key");
    };
    $ssh->debug("Rhosts with RSA authentication failed: Can't load private host key."),
        return 0 if $@;

    my $user = $ssh->{user};
    $packet = Net::SSH::Perl::Packet->new($ssh, type => SSH_CMSG_AUTH_RHOSTS_RSA);
    $packet->put_str($user);
    $packet->put_32bit($private_key->{bits});
    $packet->put_mp_int($private_key->{e});
    $packet->put_mp_int($private_key->{n});
    $packet->send;

    $packet = Net::SSH::Perl::Packet->read($ssh);
    my $type = $packet->type;
    if ($type == SSH_SMSG_FAILURE) {
        $ssh->debug("Server refused our rhosts authentication or host key.");
        return 0;
    }

    if ($type != SSH_SMSG_AUTH_RSA_CHALLENGE) {
        croak sprintf "Protocol error during RSA authentication: %d", $type;
    }
    my $challenge = $packet->get_mp_int;

    $ssh->debug("Received RSA challenge for host key from server.");

    _respond_to_rsa_challenge($ssh, $challenge, $private_key);

    $packet = Net::SSH::Perl::Packet->read($ssh);
    $type = $packet->type;
    if ($type == SSH_SMSG_SUCCESS) {
        $ssh->debug("Rhosts or /etc/hosts.equiv with RSA host authentication accepted by server.");
        return 1;
    }
    elsif ($type != SSH_SMSG_FAILURE) {
        croak "Protocol error waiting RSA auth response: $type";
    }

    $ssh->debug("Rhosts or /hosts.equiv with RSA host authentication refused.");
    return 0;
}

1;
