# $Id: Util.pm,v 1.8 2001/02/28 23:26:04 btrott Exp $

package Net::SSH::Perl::Util;
use strict;

use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Constants qw/:hosts PRIVATE_KEY_ID_STRING
    SSH_CMSG_AUTH_RSA_RESPONSE/;
use Net::SSH::Perl::Cipher;
use Carp qw/croak/;

use vars qw/$VERSION/;
use Digest::MD5 qw/md5/;
use Math::GMP;
use String::CRC32;

use vars qw/@EXPORT_OK %EXPORT_TAGS/;
use Exporter;
use base qw/Exporter/;

@EXPORT_OK = qw/
    _crc32
    _compute_session_id
    _mp_linearize
    _check_host_in_hostfile
    _add_host_to_hostfile
    _load_private_key
    _load_public_key
    _respond_to_rsa_challenge
    _rsa_public_encrypt
    _rsa_private_decrypt
    _read_passphrase
/;
%EXPORT_TAGS = (
    hosts => [ qw/_check_host_in_hostfile _add_host_to_hostfile/ ],
    rsa   => [ qw/_rsa_public_encrypt _rsa_private_decrypt _respond_to_rsa_challenge/ ],
    mp    => [ qw/_compute_session_id _mp_linearize/ ],
    all   => [ @EXPORT_OK ],
);

## crc32 checksum.

sub _crc32 {
    crc32($_[0], 0xFFFFFFFF) ^ 0xFFFFFFFF;
}

## mp utility functions.
sub _compute_session_id {
    my($check_bytes, $host, $public) = @_;
    my $id;
    $id .= _mp_linearize(int(($host->{bits}+7)/8), $host->{n});
    $id .= _mp_linearize(int(($public->{bits}+7)/8), $public->{n});
    $id .= $check_bytes;
    md5($id);
}

sub _mp_linearize {
    my($len, $key) = @_;
    my($aux, @res, $i) = ($key);
    for ($i=$len; $i>=4; $i-=4) {
        my $limb = Math::GMP::uintify_gmp($aux);
        unshift @res, $limb;
        $aux = Math::GMP::div_2exp_gmp($aux, 32);
    }
    for (; $i>0; $i--) {
        unshift @res, Math::GMP::uintify_gmp($aux);
        $aux = Math::GMP::div_2exp_gmp($aux, 8);
    }
    join '', map pack("N", $_), @res;
}

## host utility functions.
sub _check_host_in_hostfile {
    my($host, $host_file, $key) = @_;
    local *FH;
    open FH, $host_file or return HOST_CHANGED; # XXX: different return?
    local($_, $/);
    $/ = "\n";
    my($status, $match, $hosts) = (HOST_NEW);
    while (<FH>) {
        chomp;
        my($hosts, $bits, $e, $n) = split /\s+/;
        for my $h (split /,/, $hosts) {
            if ($h eq $host) {
                if ($key->{bits} == $bits &&
                  "$key->{e}" eq "$e" &&
                  "$key->{n}" eq "$n") {
                    close FH;
                    return HOST_OK;
                }
                $status = HOST_CHANGED;
            }
        }
    }
    $status;
}

sub _add_host_to_hostfile {
    my($host, $host_file, $key) = @_;
    open FH, ">>" . $host_file or croak "Can't write to $host_file: $!";
    print FH join(' ', $host, $key->{bits}, $key->{e}, $key->{n}), "\n";
    close FH or croak "Can't close $host_file: $!";
}

## other.

sub _load_public_key {
    my($key_file) = @_;

    local *FH;
    open FH, $key_file or croak "Can't open $key_file: $!";
    my $c = do { local $/; <FH> };
    close FH or die "Can't close $key_file: $!";

    my $buffer = Net::SSH::Perl::Buffer->new;
    $buffer->append($c);

    my $id = $buffer->bytes(0, length(PRIVATE_KEY_ID_STRING), "");
    croak "Bad key file $key_file." unless $id eq PRIVATE_KEY_ID_STRING;
    $buffer->bytes(0, 1, "");

    $buffer->get_char;
    $buffer->get_int32;

    my $key = {};
    $key->{bits} = $buffer->get_int32;
    $key->{n} = $buffer->get_mp_int;
    $key->{e} = $buffer->get_mp_int;

    my $comment = $buffer->get_str;

    wantarray ? ($key, $comment) : $key;
}

sub _load_private_key {
    my($key_file, $passphrase) = @_;

    local *FH;
    open FH, $key_file or croak "Can't open $key_file: $!";
    my $c = do { local $/; <FH> };
    close FH or die "Can't close $key_file: $!";

    my $buffer = Net::SSH::Perl::Buffer->new;
    $buffer->append($c);

    my $id = $buffer->bytes(0, length(PRIVATE_KEY_ID_STRING), "");
    croak "Bad key file $key_file." unless $id eq PRIVATE_KEY_ID_STRING;
    $buffer->bytes(0, 1, "");

    my $cipher_type = unpack "c", $buffer->get_char;
    $buffer->get_int32;  ## Reserved data.

    my $key = {};
    $key->{bits} = $buffer->get_int32;
    $key->{n} = $buffer->get_mp_int;
    $key->{e} = $buffer->get_mp_int;

    my $comment = $buffer->get_str;

    my $cipher_name = Net::SSH::Perl::Cipher::name($cipher_type);
    unless (Net::SSH::Perl::Cipher::supported($cipher_type)) {
        croak sprintf "Unsupported cipher '%s' used in key file '%s'",
            $cipher_name, $key_file;
    }

    my $ciph = Net::SSH::Perl::Cipher->new_from_key_str($cipher_name, $passphrase);
    my $decrypted = $ciph->decrypt($buffer->bytes($buffer->offset));
    $buffer->empty;
    $buffer->append($decrypted);

    my $check1 = ord $buffer->get_char;
    my $check2 = ord $buffer->get_char;
    if ($check1 != ord($buffer->get_char) ||
        $check2 != ord($buffer->get_char)) {
        croak "Bad passphrase supplied for key file $key_file";
    }

    $key->{d} = $buffer->get_mp_int;
    $key->{u} = $buffer->get_mp_int;
    $key->{p} = $buffer->get_mp_int;
    $key->{q} = $buffer->get_mp_int;

    wantarray ? ($key, $comment) : $key;
}

sub _read_passphrase {
    my($prompt) = @_;
    print $prompt;
    require Term::ReadKey;
    Term::ReadKey->import;
    ReadMode('noecho');
    chomp(my $pwd = ReadLine(0));
    ReadMode('restore');
    print "\n";
    $pwd;
}

## rsa utility functions.

sub _respond_to_rsa_challenge {
    my($ssh, $challenge, $key) = @_;

    $challenge = _rsa_private_decrypt($challenge, $key);
    my $buf = _mp_linearize(32, $challenge);
    my $response = md5($buf, $ssh->session_id);

    $ssh->debug("Sending response to host key RSA challenge.");

    my $packet = $ssh->packet_start(SSH_CMSG_AUTH_RSA_RESPONSE);
    $packet->put_chars($response);
    $packet->send;
}

sub _rsa_public_encrypt {
    my($input, $key) = @_;
    my $bits = Math::GMP::sizeinbase_gmp($input, 2);
    my $input_len = int(($bits + 7) / 8);
    my $len = int(($key->{bits} + 7) / 8);

    my $aux = Math::GMP->new(2);
    for my $i (2..$len-$input_len-2) {
        my $byte = 0;
        {
            $byte = int rand 128;
            redo if $byte == 0;
        }
        $aux = Math::GMP::mul_2exp_gmp($aux, 8);
        Math::GMP::add_ui_gmp($aux, $byte);
    }
    $aux = Math::GMP::mul_2exp_gmp($aux, 8 * ($input_len + 1));
    $aux = Math::GMP->new($aux + $input);

    _rsa_public($aux, $key);
}

sub _rsa_public {
    my($input, $key) = @_;
    Math::GMP::powm_gmp($input, $key->{e}, $key->{n});
}

sub _rsa_private_decrypt {
    my($data, $key) = @_;

    my $output = _rsa_private($data, $key);

    my $len = int(($key->{bits} + 7) / 8);
    my $aux = Math::GMP->new($output);
    my $res = "";
    my $i;
    for ($i=$len; $i>=4; $i-=4) {
        my $limb = Math::GMP::uintify_gmp($aux);
        $res = pack("N", $limb) . $res;
        $aux = Math::GMP::div_2exp_gmp($aux, 32);
    }
    for (; $i>0; $i--) {
        $res = pack("N", Math::GMP::uintify_gmp($aux)) . $res;
        $aux = Math::GMP::div_2exp_gmp($aux, 8);
    }
    unless (ord(substr $res, 0, 1) == 0 && ord(substr $res, 1, 1) == 2) {
        croak "Bad result from rsa_private_decrypt";
    }
    for ($i=2; $i<$len && ord substr $res, $i, 1; $i++) { }

    my $a = Math::GMP::mod_2exp_gmp($output, 8 * ($len - $i - 1));
}

sub _rsa_private {
    my($input, $key) = @_;
    my($dp, $dq, $p2, $q2, $k);

    $dp = $key->{d} % ($key->{p}-1);
    $dq = $key->{d} % ($key->{q}-1);

    $p2 = Math::GMP::powm_gmp($input % $key->{p}, $dp, $key->{p});
    $q2 = Math::GMP::powm_gmp($input % $key->{q}, $dq, $key->{q});

    $k = (($q2 - $p2) * $key->{u}) % $key->{q};
    $p2 + ($key->{p} * $k);
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Util - Shared utility functions

=head1 SYNOPSIS

    use Net::SSH::Perl::Util qw( ... );

=head1 DESCRIPTION

I<Net::SSH::Perl::Util> contains a variety of exportable utility
functions used by the various I<Net::SSH::Perl> modules. These
range from hostfile routines, to RSA encryption routines, etc.

The routines are exportable by themselves, ie.

    use Net::SSH::Perl::Util qw( routine_name );

In addition, some of the routines are grouped into bundles that
you can pull in by export tag, ie.

    use Net::SSH::Perl::Util qw( :bundle );

The groups are:

=over 4

=item * hosts

Routines associated with hostfile-checking, addition, etc.
Contains C<_check_host_in_hostfile> and C<_add_host_to_hosfile>.

=item * rsa

Routines associated with RSA encryption, decryption, and
authentication. Contains C<_rsa_public_encrypt>,
C<_rsa_private_decrypt>, and C<_respond_to_rsa_challenge>.

=item * mp

Routines associated with multiple-precision integers and the
generation and manipulation of same. Contains C<_mp_linearize>
and C<_compute_session_id>.

=item * all

All routines. Contains all of the routines listed below.

=back

=head1 FUNCTIONS

=head2 _crc32($data)

Returns a CRC32 checksum of I<$data>. This uses I<String::CRC32>
internally to do its magic, with the caveat that the "init state"
of the checksum is C<0xFFFFFFFF>, and the result is xor-ed with
C<0xFFFFFFFF>.

=head2 _compute_session_id($check_bytes, $host_key, $public_key)

Given the check bytes (I<$check_bytes>) and the server host and
public keys (I<$host_key> and I<$public_key>, respectively),
computes the session ID that is then used to uniquely identify
the session between the server and client.

I<$host_key> and I<$public_key> should be hash references with
three keys: I<bits>, I<n>, and I<e>. I<n> and I<e> should be
multiple-precision integers (I<Math::GMP> objects).

Returns the session ID.

=head2 _mp_linearize($length, $key)

Converts a multiple-precision integer I<$key> into a byte string.
I<$length> should be the number of bytes to linearize, which is
generally the number of bytes in the key.

Note that, unlike the key arguments to C<_compute_session_id>,
I<$key> here is just the multiple-precision integer, I<not>
the hash reference.

Returns the linearized string.

=head2 _check_host_in_hostfile($host, $host_file, $host_key)

Looks up I<$host> in I<$host_file> and checks the stored host
key against I<$host_key> to determine the status of the host.

If the host is not found, returns HOST_NEW.

If the host is found, and the keys match, returns HOST_OK.

If the host is found, and the keys don't match, returns
HOST_CHANGED, which generally indicates a problem.

=head2 _add_host_to_hostfile($host, $host_file, $host_key)

Opens up the known hosts file I<$host_file> and adds an
entry for I<$host> with host key I<$host_key>. Dies if
I<$host_file> can't be opened for writing.

=head2 _load_public_key($key_file)

Given the location of a public key file I<$key_file>, reads
the public key from that file.

If called in list context, returns the key and the comment
associated with the key. If called in scalar context,
returns only the key.

Dies if: the key file I<$key_file> can't be opened for
reading; or the key file is "bad" (the ID string in the
file doesn't match the PRIVATE_KEY_ID_STRING constant).

The key returned is in the form of a public key--a hash
reference with three keys: I<bits>, I<n>, and I<e>. I<n>
and I<e> and multiple-precision integers (I<Math::GMP>
objects).

=head2 _load_private_key($key_file, $passphrase)

Given the location of a private key file I<$key_file>,
and an optional passphrase to decrypt the key, reads the
private key from that file.

If called in list context, returns the key and the comment
associated with the key. If called in scalar context,
returns only the key.

Dies if: the key file I<$key_file> can't be opened for
reading; the key file is "bad" (the ID string in the file
doesn't match the PRIVATE_KEY_ID_STRING constant); the
file is encrypted using an unsupported encryption cipher;
or the passphrase I<$passphrase> is incorrect.

The key returned is in the form of a private key--a hash
reference with there keys: I<bits>, I<n>, I<e>, I<d>,
I<u>, I<p>, and I<q>. All but I<bits> are multiple-precision
integers (I<Math::GMP> objects).

=head2 _read_passphrase($prompt)

Uses I<Term::ReadKey> with echo off to read a passphrase,
after issuing the prompt I<$prompt>. Echo is restored
once the passphrase has been read.

=head2 _respond_to_rsa_challenge($ssh, $challenge, $key)

Decrypts the RSA challenge I<$challenge> using I<$key>,
then the response (MD5 of decrypted challenge and session
ID) to the server, using the I<$ssh> object, in an
RSA response packet.

=head2 _rsa_public_encrypt($data, $key)

Encrypts the multiple-precision integer I<$data> (a
I<Math::GMP> object) using I<$key>.

Returns the encrypted data, also a I<Math::GMP> object.

=head2 _rsa_private_decrypt($data, $key)

Decrypts the multiple-precision integer I<$data> (a
I<Math::GMP> object) using I<$key>.

Returns the decrypted data, also a I<Math::GMP> object.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
