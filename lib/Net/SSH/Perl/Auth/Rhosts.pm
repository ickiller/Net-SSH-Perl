package Net::SSH::Perl::Auth::Rhosts;

use strict;
use Carp qw/croak/;

use Net::SSH::Perl::Constants qw/
    SSH_SMSG_FAILURE
    SSH_SMSG_SUCCESS
    SSH_CMSG_AUTH_RHOSTS/;

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

    $ssh->debug("Trying rhosts authentication.");

    $packet = $ssh->packet_start(SSH_CMSG_AUTH_RHOSTS);
    $packet->put_str($ssh->{user});
    $packet->send;

    $packet = Net::SSH::Perl::Packet->read($ssh);
    my $type = $packet->type;
    if ($type == SSH_SMSG_SUCCESS) {
        return 1;
    }
    elsif ($type != SSH_SMSG_FAILURE) {
        croak "Protocol error: got $type in response to rhosts auth";
    }

    return 0;
}

1;
