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
    $packet = Net::SSH::Perl::Packet->new($ssh, type => SSH_CMSG_AUTH_PASSWORD);
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
