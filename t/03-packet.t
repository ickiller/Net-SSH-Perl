# $Id: 03-packet.t,v 1.3 2001/02/22 00:12:55 btrott Exp $

use strict;

use Net::SSH::Perl;
use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Constants qw/:msg/;

use Test;
BEGIN { plan tests => 7 }

my $ssh = Net::SSH::Perl->new("dummy");
my $packet;

## Okay, so you shouldn't ever be doing this,
## in real usage...
tie *FH, 'StringThing';
$ssh->{session}{sock} = \*FH;

## Test basic functionality: send a packet with a string...
$packet = Net::SSH::Perl::Packet->new($ssh, type => SSH_CMSG_USER);
ok($packet);
$packet->put_str("foo");
$packet->send;

## ... And read it back.
$packet = Net::SSH::Perl::Packet->read($ssh);
ok($packet);
ok($packet->type, SSH_CMSG_USER);
ok($packet->get_str, "foo");

## Test read_expect. Send a SUCCESS message, expect a FAILURE
## message. This should croak.
Net::SSH::Perl::Packet->new($ssh, type => SSH_SMSG_SUCCESS)->send;
eval {
    $packet = Net::SSH::Perl::Packet->read_expect($ssh, SSH_SMSG_FAILURE);
};
my $expected = sprintf "type %s, got %s", SSH_SMSG_FAILURE, SSH_SMSG_SUCCESS;
ok($@ && $@ =~ /$expected/);

## Test leftover functionality. Send two packets
## that will both get placed into the StringThing buffer...
Net::SSH::Perl::Packet->new($ssh, type => SSH_SMSG_FAILURE)->send;
Net::SSH::Perl::Packet->new($ssh, type => SSH_CMSG_EOF)->send;

## Reading the first packet will read the entire rest of
## the buffer: *both* packets. The internal leftover
## buffer should be split up based on the packet lengths.
## First read reads entire buffer, grabs first packet...
$packet = Net::SSH::Perl::Packet->read($ssh);
ok($packet->type == SSH_SMSG_FAILURE);

## ... Second read grabs leftover buffer, grabs second packet.
$packet = Net::SSH::Perl::Packet->read($ssh);
ok($packet->type == SSH_CMSG_EOF);

package StringThing;
use strict;
use Carp qw/croak/;

sub TIEHANDLE { bless { buf => "", offset => 0 }, shift; }
sub WRITE { $_[0]->{buf} .= $_[1] }

sub READ {
    croak "Nothing to read" unless $_[0]->{buf};
    $_[1] = substr $_[0]->{buf}, $_[0]->{offset}, $_[2];
    $_[0]->{offset} = _min(length $_[0]->{buf}, $_[0]->{offset} + $_[2]);
}

sub _min { $_[0] < $_[1] ? $_[0] : $_[1] }
