# $Id: Key.pm,v 1.9 2001/05/03 16:52:24 btrott Exp $

package Net::SSH::Perl::Key;
use strict;

use Digest::MD5 qw( md5 );
use Digest::SHA1 qw( sha1 );
use Digest::BubbleBabble qw( bubblebabble );

sub new {
    my $class = shift;
    if ($class eq __PACKAGE__) {
        $class .= "::" . shift();
        eval "use $class;";
        die "Key class '$class' is unsupported: $@" if $@;
    }
    my $key = bless {}, $class;
    $key->init(@_);
    $key;
}

BEGIN {
    no strict 'refs';
    for my $meth (qw( read_private keygen extract_public )) {
        *$meth = sub {
            my $class = shift;
            if ($class eq __PACKAGE__) {
                $class .= "::" . shift();
                eval "use $class;";
                die "Key class '$class' is unsupported: $@" if $@;
            }
            $class->$meth(@_);
        };
    }
}

sub init;
sub extract_public;
sub dump_public;
sub as_blob;
sub equal;

sub fingerprint {
    my $key = shift;
    my($type) = @_;
    my $data = $key->fingerprint_raw;
    $type && $type eq 'bubblebabble' ?
        _fp_bubblebabble($data) : _fp_hex($data);
}

sub _fp_bubblebabble { bubblebabble( Digest => sha1($_[0]) ) }

sub _fp_hex { join ':', map { sprintf "%02x", ord } split //, md5($_[0]) }

1;
__END__

=head1 NAME

Net::SSH::Perl::Key - Public or private key abstraction

=head1 SYNOPSIS

    use Net::SSH::Perl::Key;
    my $key = Net::SSH::Perl::Key->new;

=head1 DESCRIPTION

I<Net::SSH::Perl::Key> implements an abstract base class interface
to key objects (either DSA or RSA keys, currently). The underlying
implementation for RSA is an internal, hash-reference implementation;
the DSA implementation uses I<Crypt::DSA>.

=head1 USAGE

=head2 Net::SSH::Perl::Key->new($key_type, @args)

Creates a new object of type I<Net::SSH::Perl::Key::$key_type>,
after loading the class implementing I<$key_type>. I<$key_type>
should be either C<DSA> or C<RSA>, currently; these are the
only supported key implementations at the moment.

I<@args>, if present, are passed directly to the I<init> method
of the subclass implementation; take a look at the docs for the
subclasses to determine what I<@args> can contain.

Returns the new key object, which is blessed into the subclass.

=head2 Net::SSH::Perl::Key->read_private($key_type, $file [, $pass])

Reads a private key of type I<$key_type> out of the key file
I<$file>. If the private key is encrypted, an attempt will be
made to decrypt it using the passphrase I<$pass>; if I<$pass>
is not provided, the empty string will be used. An empty
passphrase can be a handy way of providing password-less access
using publickey authentication.

If for any reason loading the key fails, returns I<undef>; most
of the time, if loading the key fails, it's because the passphrase
is incorrect. If you first tried to read the key using an empty
passphrase, this might be a good time to ask the user for the
actual passphrase. :)

Returns the new key object, which is blessed into the subclass
denoted by I<$key_type> (either C<DSA> or C<RSA>).

=head2 Net::SSH::Perl::Key->keygen($key_type, $bits)

Generates a new key and returns that key. The key returned is
the private key, which (presumably) contains all of the public
key data, as well. I<$bits> is the number of bits in the key.

Your I<$key_type> implementation may not support key generation;
if not, calling this method is a fatal error.

Returns the new key object, which is blessed into the subclass
denoted by I<$key_type> (either C<DSA> or C<RSA>).

=head2 Net::SSH::Perl::Key->extract_public($key_type, $key_string)

Given a key string I<$key_string>, which should be a textual
representation of the public portion of a key of I<$key_type>,
extracts the key attributes out of that string. This is used to
extract public keys out of entries in F<known_hosts> and public
identity files.

Returns the new key object, which is blessed into the subclass
denoted by I<$key_type> (either C<DSA> or C<RSA>).

=head2 $key->write_private([ $file [, $pass] ])

Writes out the private key I<$key> to I<$file>, and encrypts
it using the passphrase I<$pass>. If I<$pass> is not provided,
the key is unencrypted, and the only security protection is
through filesystem protections.

If I<$file> is not provided, returns the content that would
have been written to the key file.

=head2 $key->dump_public

Performs the inverse of I<extract_public>: takes a key I<$key>
and dumps out a textual representation of the public portion
of the key. This is used when writing public key entries to
F<known_hosts> and public identity files.

Returns the textual representation.

=head2 $key->as_blob

Returns a string representation of the public portion of the
key; this is I<not> the same as I<dump_public>, which is
intended to match the format used in F<known_hosts>, etc.
The return value of I<as_blob> is used as an intermediary in
computing other values: the key fingerprint, the known hosts
representation, etc.

=head2 $key->equal($key2)

Returns true if the public portions of I<$key> are equal to
those of I<$key2>, and false otherwise. This is used when
comparing server host keys to keys in F<known_hosts>.

=head2 $key->fingerprint([ I<$type> ])

Returns a fingerprint of I<$key>. The default fingerprint is
a hex representation; if I<$type> is equal to C<bubblebabble>,
the Bubble Babble representation of the fingerprint is used
instead. The former uses an I<MD5> digest of the public key,
and the latter uses a I<SHA-1> digest.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
