# $Id: Key.pm,v 1.7 2001/05/03 03:05:55 btrott Exp $

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
    for my $meth (qw( read_private keygen )) {
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
sub sign;
sub verify;
sub as_blob;
sub equal;

sub fingerprint {
    my $key = shift;
    my($type) = @_;
    my $data = $key->fingerprint_raw;
    $type eq 'bubblebabble' ? _fp_bubblebabble($data) : _fp_hex($data);
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

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
