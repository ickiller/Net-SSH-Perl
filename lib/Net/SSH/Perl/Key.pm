# $Id: Key.pm,v 1.6 2001/05/02 06:08:46 btrott Exp $

package Net::SSH::Perl::Key;
use strict;

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
sub fingerprint;

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
