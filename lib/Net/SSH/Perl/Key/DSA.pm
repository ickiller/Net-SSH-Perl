# $Id: DSA.pm,v 1.13 2001/05/02 03:27:52 btrott Exp $

package Net::SSH::Perl::Key::DSA;
use strict;

use Net::SSH::Perl::Buffer qw( SSH2 );
use Net::SSH::Perl::Constants qw( KEX_DSS SSH_COMPAT_BUG_SIGBLOB );
use Net::SSH::Perl::Util qw( :ssh2mp );

use Net::SSH::Perl::Key;
use base qw( Net::SSH::Perl::Key );

use MIME::Base64;
use Crypt::DSA;
use Crypt::DSA::Key;
use Carp qw( croak );
use Digest::SHA1 qw( sha1 );
use Digest::MD5 qw( md5 );

use constant INTBLOB_LEN => 20;

sub init {
    my $key = shift;
    $key->{dsa} = Crypt::DSA::Key->new;

    my($blob, $datafellows) = @_;

    if ($blob) {
        my $b = Net::SSH::Perl::Buffer->new;
        $b->append($blob);
        my $ktype = $b->get_str;
        croak __PACKAGE__, "->init: cannot handle type '$ktype'"
            unless $ktype eq KEX_DSS;
        my $dsa = Crypt::DSA::Key->new;
        $dsa->p( $b->get_mp_int );
        $dsa->q( $b->get_mp_int );
        $dsa->g( $b->get_mp_int );
        $dsa->pub_key( $b->get_mp_int );
        $key->{dsa} = $dsa;
    }

    if ($datafellows) {
        $key->{datafellows} = $datafellows;
    }
}

sub keygen {
    my $class = shift;
    my($bits, $datafellows) = @_;
    my $dsa = Crypt::DSA->new;
    my $key = $class->new(undef, $datafellows);
    $key->{dsa} = $dsa->keygen(Size => $bits, Verbosity => 1);
    $key;
}

sub size { bitsize($_[0]->{dsa}->p) }

sub read_private {
    my $class = shift;
    my($key_file, $passphrase, $datafellows) = @_;

    my $key = $class->new(undef, $datafellows);
    $key->{dsa} = Crypt::DSA::Key->new(
                     Filename => $key_file,
                     Type     => 'PEM',
                     Password => $passphrase
            );
    return unless $key->{dsa};

    $key;
}

sub write_private {
    my $key = shift;
    my($key_file, $passphrase) = @_;

    $key->{dsa}->write(
                    Filename => $key_file,
                    Type     => 'PEM',
                    Password => $passphrase
            );
}

sub extract_public {
    my $class = shift;
    my($blob) = @_;
    my($type, $data) = split /\s+/, $blob;
    $class->new( decode_base64($data) );
}

sub dump_public { KEX_DSS . ' ' . encode_base64( $_[0]->as_blob, '' ) }

sub sign {
    my $key = shift;
    my($data) = @_;
    my $dsa = Crypt::DSA->new;
    my $sig = $dsa->sign(Digest => sha1($data), Key => $key->{dsa});
    my $sigblob = '';
    $sigblob .= mp2bin($sig->r, INTBLOB_LEN);
    $sigblob .= mp2bin($sig->s, INTBLOB_LEN);

    if (${$key->{datafellows}} & SSH_COMPAT_BUG_SIGBLOB) {
        return $sigblob;
    }
    else {
        my $b = Net::SSH::Perl::Buffer->new;
        $b->put_str(KEX_DSS);
        $b->put_str($sigblob);
        $b->bytes;
    }
}

sub verify {
    my $key = shift;
    my($signature, $data) = @_;
    my $sigblob;

    if (${$key->{datafellows}} & SSH_COMPAT_BUG_SIGBLOB) {
        $sigblob = $signature;
    }
    else {
        my $b = Net::SSH::Perl::Buffer->new;
        $b->append($signature);
        my $ktype = $b->get_str;
        croak "Can't verify type ", $ktype unless $ktype eq KEX_DSS;
        $sigblob = $b->get_str;
    }

    my $sig = Crypt::DSA::Signature->new;
    $sig->r( bin2mp(substr $sigblob, 0, INTBLOB_LEN) );
    $sig->s( bin2mp(substr $sigblob, INTBLOB_LEN) );

    my $digest = sha1($data);
    my $dsa = Crypt::DSA->new;
    $dsa->verify( Key => $key->{dsa}, Digest => $digest, Signature => $sig );
}

sub equal {
    my($keyA, $keyB) = @_;
    $keyA->{dsa}->p == $keyB->{dsa}->p &&
    $keyA->{dsa}->q == $keyB->{dsa}->q &&
    $keyA->{dsa}->g == $keyB->{dsa}->g &&
    $keyA->{dsa}->pub_key == $keyB->{dsa}->pub_key;
}

sub as_blob {
    my $key = shift;
    my $b = Net::SSH::Perl::Buffer->new;
    $b->put_str(KEX_DSS);
    $b->put_mp_int($key->{dsa}->p);
    $b->put_mp_int($key->{dsa}->q);
    $b->put_mp_int($key->{dsa}->g);
    $b->put_mp_int($key->{dsa}->pub_key);
    $b->bytes;
}

sub fingerprint {
    my $key = shift;
    my $md5 = md5( $key->as_blob );
    join ':', map { sprintf "%02x", ord } split //, $md5;
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Key::DSA - DSA key object

=head1 SYNOPSIS

    use Net::SSH::Perl::Key::DSA;
    my $key = Net::SSH::Perl::Key::DSA->new;

=head1 DESCRIPTION

I<Net::SSH::Perl::Key::DSA> subclasses I<Net::SSH::Perl::Key>
to implement a key object, SSH style. This object provides all
of the methods needed for a DSA key object; the underlying
implementation is provided by I<Crypt::DSA>, and this class
wraps around that module to provide SSH-specific functionality
(eg. taking in a I<Net::SSH::Perl::Buffer> blob and transforming
it into a key object).

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
