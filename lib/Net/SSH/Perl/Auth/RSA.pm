package Net::SSH::Perl::Auth::RSA;

use strict;
use Carp qw/croak/;

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
    my($packet);
    my $ssh = $auth->{ssh};

    my($public_key, $comment, $private_key, $auth_file);
    $auth_file = "$ENV{HOME}/.ssh/identity";
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
        croak "Protocol error during RSA authentication: $type";
    }

    my $challenge = $packet->get_mp_int;
    $ssh->debug("Received RSA challenge from server.");

    eval {
        $private_key = _load_private_key($auth_file, "");
    };
    if (!$private_key || $@) {
        my $passphrase = "";
        if ($ssh->{interactive}) {
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
        croak "Protocol error waiting RSA auth response: $type";
    }

    $ssh->debug("RSA authentication refused.");
    return 0;
}

1;
