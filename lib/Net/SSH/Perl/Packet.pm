# $Id: Packet.pm,v 1.4 2001/02/21 23:50:41 btrott Exp $

package Net::SSH::Perl::Packet;

use strict;
use Carp qw/croak/;

use Net::SSH::Perl;
use Net::SSH::Perl::Constants qw/SSH_MSG_DISCONNECT SSH_MSG_DEBUG MAX_PACKET_SIZE/;
use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Util qw/_crc32/;

sub new {
    my $class = shift;
    my $ssh   = shift;
    my $pack  = bless { ssh => $ssh, @_ }, $class;
    unless ($pack->{data}) {
        $pack->{data} = Net::SSH::Perl::Buffer->new;
        if ($pack->{type}) {
            $pack->{data}->put_int8($pack->{type});
        }
    }
    $pack;
}

sub read {
    my $class = shift;
    my $ssh = shift;
    my $sock = $ssh->sock;

    my $buffer = Net::SSH::Perl::Buffer->new;

    if (my $lo = $ssh->in_leftover) {
        $buffer->append($lo);
        $ssh->in_leftover("");
    }

    my($pad_len, $len);
    {
        $len = unpack "N", $buffer->bytes(0, 4);
        $len = 0 unless defined $len;
        $pad_len = ($len + 8) & ~7;

        if ($buffer->length < 4 + $pad_len) {
            my $buf;
            sysread $sock, $buf, 8192;
            $buffer->append($buf);
            redo;
        }
    }

    $ssh->in_leftover($buffer->bytes($pad_len+4, $buffer->length, ""));

    $buffer->bytes(0, 4, "");

    if (my $cipher = $ssh->receive_cipher) {
        my $decrypted = $cipher->decrypt($buffer->bytes);
        $buffer->empty;
        $buffer->append($decrypted);
    }

    my $crc = _crc32($buffer->bytes(0, -4));
    $buffer->bytes(0, 8 - $len % 8, "");

    my $stored_crc = unpack "N", $buffer->bytes(-4, 4);
    croak "Corrupted check bytes on input"
        unless $crc == $stored_crc;

    my $type = unpack "c", $buffer->bytes(0, 1, "");
    $buffer->bytes(-4, 4, "");  ## Cut off checksum.

    if ($type == SSH_MSG_DISCONNECT) {
        croak sprintf "Received disconnect message: %s\n", $buffer->get_str;
    }

    if ($type == SSH_MSG_DEBUG) {
        $ssh->debug(sprintf "Remote: %s", $buffer->get_str);
        return $class->read($ssh);
    }

    $class->new($ssh,
        type => $type,
        data => $buffer);
}

sub read_expect {
    my $class = shift;
    my($ssh, $type) = @_;
    my $pack = $class->read($ssh);
    if ($pack->type != $type) {
        croak sprintf "Protocol error: expected packet type %d, got %d; buffer is %s",
            $type, $pack->type, $pack->data->bytes;
    }
    $pack;
}

sub send {
    my $pack = shift;
    my $buffer = shift || $pack->{data};

    if ($buffer->length >= MAX_PACKET_SIZE - 30) {
        croak sprintf "Sending too big a packet: size %d, limit %d",
            $buffer->length, MAX_PACKET_SIZE;
    }

    my $len = $buffer->length + 4;

    my $cipher = $pack->{ssh}->send_cipher;
    #if ($cipher) {
        $buffer->insert_padding;
    #}

    my $crc = _crc32($buffer->bytes);
    $buffer->put_int32($crc);

    my $output = Net::SSH::Perl::Buffer->new;
    $output->put_int32($len);
    my $data = $cipher ?
        $cipher->encrypt($buffer->bytes) : $buffer->bytes;
    $output->put_chars($data);

    my $sock = $pack->{ssh}->sock;
    syswrite $sock, $output->bytes;
}

sub type {
    my $pack = shift;
    $pack->{type} = shift if @_;
    $pack->{type};
}

sub data { $_[0]->{data} }

sub AUTOLOAD {
    my $pack = shift;
    use vars qw/$AUTOLOAD/;
    (my $meth = $AUTOLOAD) =~ s/.*://;
    return if $meth eq "DESTROY";

    if (my $code = $pack->{data}->can($meth)) {
        $code->($pack->{data}, @_);
    }
    else {
        croak "Can't dispatch method $meth to Net::SSH::Perl::Buffer object.";
    }
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Packet - Packet layer of SSH protocol

=head1 SYNOPSIS

    use Net::SSH::Perl::Packet;

    # Send a packet to an ssh daemon.
    my $pack = Net::SSH::Perl::Packet->new($ssh, type => SSH_MSG_NONE);
    $pack->send;

    # Receive a packet.
    my $pack = Net::SSH::Perl::Packet->read($ssh);

=head1 DESCRIPTION

I<Net::SSH::Perl::Packet> implements the packet-layer piece
of the SSH protocol. Messages between server and client
are sent as binary data packets, which are encrypted
(once the two sides have agreed on the encryption
cipher, that is).

Packets are made up primarily of a packet type, which
describes the type of message and data contained
therein, and the data itself. In addition, each packet:
indicates its length in a 32-bit unsigned integer;
contains padding to pad the length of the packet to
a multiple of 8 bytes; and is verified by a 32-bit crc
checksum.

Refer to the SSH RFC for more details on the packet
protocol and the SSH protocol in general.

=head1 USAGE

=head2 Net::SSH::Perl::Packet->new($ssh, %params)

Creates/starts a new packet in memory. I<$ssh> is
a I<Net::SSH::Perl> object, which should already be connected
to an ssh daemon. I<%params> can contain the following
keys:

=over 4

=item * type

The message type of this packet. This should be one of
the values exported by I<Net::SSH::Perl::Constants> from the
I<msg> tag; for example, I<SSH_MSG_NONE>.

=item * data

A I<Net::SSH::Perl::Buffer> object containing the data in this
packet. Realistically, there aren't many times you'll need
to supply this argument: when sending a packet, it will be
created automatically; and when receiving a packet, the
I<read> method (see below) will create the buffer
automatically, as well.

=back

=head2 Net::SSH::Perl::Packet->read($ssh)

Reads a packet from the ssh daemon, blocking if necessary,
and returns that packet.

=head2 Net::SSH::Perl::Packet->read_expect($ssh, $type)

Reads the next packet from the daemon and dies if the
packet type does not match I<$type>. Otherwise returns
the read packet.

=head2 $packet->send([ $data ])

Sends a packet to the ssh daemon. I<$data> is optional,
and if supplied specifies the buffer to be sent in
the packet (should be a I<Net::SSH::Perl::Buffer> object).
In addition, I<$data>, if specified, I<must> include
the packed message type.

If I<$data> is not specified, I<send> sends the buffer
internal to the packet, which you've presumably filled
by calling the I<put_*> methods (see below).

=head2 $packet->type

Returns the message type of the packet I<$packet>.

=head2 $packet->data

Returns the message buffer from the packet I<$packet>;
a I<Net::SSH::Perl::Buffer> object.

=head2 Net::SSH::Perl::Buffer methods

Calling methods from the I<Net::SSH::Perl::Buffer> class on
your I<Net::SSH::Perl::Packet> object will automatically
invoke those methods on the buffer object internal
to your packet object (which is created when your
object is constructed). For example, if you executed
the following code:

    my $packet = Net::SSH::Perl::Packet->new($ssh, type => SSH_CMSG_USER);
    $packet->put_str($user);

this would construct a new packet object I<$packet>,
then fill its internal buffer by calling the
I<put_str> method on it.

Refer to the I<Net::SSH::Perl::Buffer> documentation
(the I<GET AND PUT METHODS> section) for more details
on those methods.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
