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
    _rsa_private
    _read_passphrase
/;
%EXPORT_TAGS = (
    hosts => [ qw/_check_host_in_hostfile _add_host_to_hostfile/ ],
    rsa   => [ qw/_rsa_public_encrypt _rsa_private_decrypt _rsa_private _respond_to_rsa_challenge/ ],
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
    local $_;
    my($match, $status, $hosts);
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
    $buffer->get_32bit;

    my $key = {};
    $key->{bits} = $buffer->get_32bit;
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
    $buffer->get_32bit;  ## Reserved data.

    my $key = {};
    $key->{bits} = $buffer->get_32bit;
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

    my $packet = Net::SSH::Perl::Packet->new($ssh, type => SSH_CMSG_AUTH_RSA_RESPONSE);
    for my $i (0..15) {
        $packet->put_char(substr $response, $i, 1);
    }
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

    Math::GMP::powm_gmp($aux, $key->{e}, $key->{n});
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

    my $a = $input % $key->{p};
    $p2 = Math::GMP::powm_gmp($a, $dp, $key->{p});

    my $b = $input % $key->{q};
    $q2 = Math::GMP::powm_gmp($b, $dq, $key->{q});

    $k = Math::GMP::mmod_gmp(($q2 - $p2) * $key->{u}, $key->{q});
    $p2 + ($key->{p} * $k);
}

1;
