# $Id: Buffer.pm,v 1.6 2001/03/09 18:37:10 btrott Exp $

package Net::SSH::Perl::Buffer;
use strict;

use Math::GMP;

sub new {
    my $class = shift;
    bless { buf => "", offset => 0 }, $class;
}

sub empty {
    my $buf = shift;
    $buf->{buf} = "";
    $buf->{offset} = 0;
}

sub append {
    my $buf = shift;
    $buf->{buf} .= $_[0];
}

sub consume {
    my $buf = shift;
    my $len = shift;
    substr $buf->{buf}, 0, $len, '';
}

sub bytes {
    my $buf = shift;
    my($off, $len, $rep) = @_;
    $off ||= 0;
    $len = length $buf->{buf} unless defined $len;
    return defined $rep ?
        substr($buf->{buf}, $off, $len, $rep) :
        substr($buf->{buf}, $off, $len);
}

sub length { length $_[0]->{buf} }
sub offset { $_[0]->{offset} }

sub dump {
    my $buf = shift;
    my @r;
    for my $c (split //, $buf->bytes(@_)) {
        push @r, sprintf "%02x", ord $c;
    }
    join ' ', @r
}

sub insert_padding {
    my $buf = shift;
    my $pad = 8 - ($buf->length + 4 - 8) % 8;
    my $junk = join '', map chr rand 128, 0..$pad-1;
    $buf->bytes(0, 0, $junk);
}

sub get_int8 {
    my $buf = shift;
    my $off = defined $_[0] ? shift : $buf->{offset};
    $buf->{offset} += 1;
    unpack "c", $buf->bytes($off, 1);
}

sub put_int8 {
    my $buf = shift;
    $buf->{buf} .= pack "c", $_[0];
}

sub get_int16 {
    my $buf = shift;
    my $off = defined $_[0] ? shift : $buf->{offset};
    $buf->{offset} += 2;
    unpack "n", $buf->bytes($off, 2);
}

sub put_int16 {
    my $buf = shift;
    $buf->{buf} .= pack "n", $_[0];
}

sub get_int32 {
    my $buf = shift;
    my $off = defined $_[0] ? shift : $buf->{offset};
    $buf->{offset} += 4;
    unpack "N", $buf->bytes($off, 4);
}

sub put_int32 {
    my $buf = shift;
    $buf->{buf} .= pack "N", $_[0];
}

sub get_char {
    my $buf = shift;
    my $off = defined $_[0] ? shift : $buf->{offset};
    $buf->{offset}++;
    $buf->bytes($off, 1);
}

sub put_char {
    my $buf = shift;
    $buf->{buf} .= $_[0];
}
*put_chars = \&put_char;

sub get_str {
    my $buf = shift;
    my $off = defined $_[0] ? shift : $buf->{offset};
    my $len = $buf->get_int32;
    $buf->{offset} += $len;
    $buf->bytes($off+4, $len);
}

sub put_str {
    my $buf = shift;
    my $str = shift;
    $str = "" unless defined $str;
    $buf->put_int32(CORE::length($str));
    $buf->{buf} .= $str;
}

sub get_mp_int {
    my $buf = shift;
    my $off = defined $_[0] ? shift : $buf->{offset};
    my $bits = unpack "n", $buf->bytes($off, 2);
    my $bytes = int(($bits + 7) / 8);
    my $hex = join '', map { sprintf "%02x", ord } split //, 
        $buf->bytes($off+2, $bytes);
    $buf->{offset} += 2 + $bytes;
    Math::GMP->new("0x$hex");
}

sub put_mp_int {
    my $buf = shift;
    my $int = shift;
    my $bits = Math::GMP::sizeinbase_gmp($int, 2);
    my $hex_size = Math::GMP::sizeinbase_gmp($int, 16);
    my $tmp = Math::GMP::get_str_gmp($int, 16);
    $tmp = "0$tmp" if CORE::length($tmp) % 2;
    $tmp =~ s/(..)/ chr hex $1 /ge;
    $buf->put_int16($bits);
    $buf->put_chars($tmp);
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Buffer - Low-level read/write buffer class

=head1 SYNOPSIS

    use Net::SSH::Perl::Buffer;
    my $buffer = Net::SSH::Perl::Buffer->new;

    ## Add a 32-bit integer.
    $buffer->put_int32(10932930);

    ## Get it back.
    my $int = $buffer->get_int32;

=head1 DESCRIPTION

I<Net::SSH::Perl::Buffer> implements the low-level binary
buffer needed by the I<Net::SSH::Perl> suite. Specifically,
a I<Net::SSH::Perl::Buffer> object is what makes up the
data segment of a packet transferred between server and
client (a I<Net::SSH::Perl::Packet> object).

Buffers contain integers, strings, characters, etc. Because
of the use of GMP integers in SSH, buffers can also contain
multiple-precision integers (represented internally by
I<Math::GMP> objects).

Note: the method documentation here is in what some might
call a slightly backwards order. The reason for this is that
the get and put methods (listed first) are probably what
most users/developers of I<Net::SSH::Perl> need to care
about; they're high-level methods used to get/put data
from the buffer. The other methods (I<LOW-LEVEL METHODS>)
are much more low-level, and typically you won't need to
use them explicitly.

=head1 GET AND PUT METHODS

All of the I<get_*> and I<put_*> methods respect the
internal offset state in the buffer object. This means
that, for example, if you call I<get_int16> twice in a
row, you can be ensured that you'll get the next two
16-bit integers in the buffer. You don't need to worry
about the number of bytes a certain piece of data takes
up, for example.

=head2 $buffer->get_int8

Returns the next 8-bit integer from the buffer (which
is really just the ASCII code for the next character/byte
in the buffer).

=head2 $buffer->put_int8

Appends an 8-bit integer to the buffer (which is really
just the character corresponding to that integer, in
ASCII).

=head2 $buffer->get_int16

Returns the next 16-bit integer from the buffer.

=head2 $buffer->put_int16($integer)

Appends a 16-bit integer to the buffer.

=head2 $buffer->get_int32

Returns the next 32-bit integer from the buffer.

=head2 $buffer->put_int32($integer)

Appends a 32-bit integer to the buffer.

=head2 $buffer->get_char

More appropriately called I<get_byte>, perhaps, this
returns the next byte from the buffer.

=head2 $buffer->put_char($bytes)

Appends a byte (or a sequence of bytes) to the buffer.
There is no restriction on the length of the byte
string I<$bytes>; if it makes you uncomfortable to call
I<put_char> to put multiple bytes, you can instead
call this method as I<put_chars>. It's the same thing.

=head2 $buffer->get_str

Returns the next "string" from the buffer. A string here
is represented as the length of the string (a 32-bit
integer) followed by the string itself.

=head2 $buffer->put_str($string)

Appends a string (32-bit integer length and the string
itself) to the buffer.

=head2 $buffer->get_mp_int

Returns a I<Math::GMP> object representing a multiple
precision integer read from the buffer. In the buffer
itself, an mp_int is represented by a 16-bit integer
(the number of bits in the integer), and the integer
itself.

=head2 $buffer->put_mp_int($mp_int)

Appends a multiple precision integer (16-bit integer
bit count and the integer itself) to the buffer.

=head1 LOW-LEVEL METHODS

=head2 Net::SSH::Perl::Buffer->new

Creates a new buffer object and returns it. The buffer is
empty.

This method takes no arguments.

=head2 $buffer->append($bytes)

Appends raw data I<$bytes> to the end of the in-memory
buffer. Generally you don't need to use this method
unless you're initializing an empty buffer, because
when you need to add data to a buffer you should
generally use one of the I<put_*> methods.

=head2 $buffer->empty

Empties out the buffer object.

=head2 $buffer->bytes([ $offset [, $length [, $replacement ]]])

Behaves exactly like the I<substr> built-in function,
except on the buffer I<$buffer>. Given no arguments,
I<bytes> returns the entire buffer; given one argument
I<$offset>, returns everything from that position to
the end of the string; given I<$offset> and I<$length>,
returns the segment of the buffer starting at I<$offset>
and consisting of I<$length> bytes; and given all three
arguments, replaces that segment with I<$replacement>.

This is a very low-level method, and you generally
won't need to use it.

Also be warned that you should not intermix use of this
method with use of the I<get_*> and I<put_*> methods;
the latter classes of methods maintain internal state
of the buffer offset where arguments will be gotten from
and put, respectively. The I<bytes> method gives no
thought to this internal offset state.

=head2 $buffer->length

Returns the length of the buffer object.

=head2 $buffer->offset

Returns the internal offset state.

If you insist on intermixing calls to I<bytes> with calls
to the I<get_*> and I<put_*> methods, you'll probably
want to use this method to get some status on that
internal offset.

=head2 $buffer->dump

Returns a hex dump of the buffer.

=head2 $buffer->insert_padding

A helper method: pads out the buffer so that the length
of the transferred packet will be evenly divisible by
8, which is a requirement of the SSH protocol.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
