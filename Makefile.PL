# $Id: Makefile.PL,v 1.17 2001/05/02 23:40:44 btrott Exp $

use ExtUtils::MakeMaker qw( prompt WriteMakefile );
use strict;

my %BASE_PREREQS = (
    1 => {
        'String::CRC32'     => '1.2',
        'Math::GMP'         => '1.04',
        'Digest::MD5'       => 0,
    },

    2 => {
        'Digest::MD5'       => 0,
        'Digest::SHA1'      => 0,
        'Crypt::DSA'        => '0.11',
        'Crypt::DH'         => '0.01',
        'Convert::ASN1'     => '0.10',
        'Math::Pari'        => '2.001804',
        'MIME::Base64'      => 0,
        'Digest::HMAC_MD5'  => 0,
        'Digest::HMAC_SHA1' => 0,
        'Convert::PEM'      => '0.04',
    },
);

for my $i (1..2) {
    for my $mod (keys %{ $BASE_PREREQS{$i} }) {
        $BASE_PREREQS{3}{$mod} = $BASE_PREREQS{$i}{$mod};
    }
}

my %prereq;

my @cryptmod = (
    [ 'IDEA', 'Crypt::IDEA' ],
    [ 'DES', 'Crypt::DES' ],
    [ 'DES3', 'Crypt::DES' ],
    [ 'Blowfish', 'Crypt::Blowfish' ],
    [ 'RC4', '' ],
);

print<<MSG;
This is Net::SSH::Perl.

MSG

print<<MSG;
As of version 1.00, Net::SSH::Perl supports both the SSH1 and
SSH2 protocols natively. The two protocols have different
module prerequisitives, so you need to decide which protocol(s)
you plan to use. If you use one or the other, only those modules
for your chosen protocol will be installed; if you choose both,
all of the supporting modules will be installed. Please choose
the protocols you'd like to use from the following list ("Both"
is the default).

MSG

for my $i (1..2) {
    printf "    [%d] SSH%d\n", $i, $i;
}
printf "    [3] Both SSH1 and SSH2\n";

my $p = prompt("\nWhich protocol(s) do you plan to use?", 3);
print "\n";

for my $mod (keys %{ $BASE_PREREQS{$p} }) {
    $prereq{$mod} = $BASE_PREREQS{$p}{$mod};
}

print<<MSG;

Some of the Net::SSH::Perl ciphers depend on a Crypt:: module
from CPAN. You may already have the necessary modules
installed, in which case you don't need to bother with
this step. Otherwise you'll need to install at least one
cipher to use Net::SSH::Perl. Please choose at least one from
the following list (Crypt::IDEA is the default).

MSG
my $i = 1;
for my $ciph (sort { $a->[0] <=> $b->[0] } @cryptmod) {
    printf "    [%d] %s\n", $i++, $ciph->[0];
}
my $c = prompt("\nEnter your choices, separated by spaces:", 1);
print "\n";

for my $id (split /\s+/, $c) {
    next unless $cryptmod[$id-1]->[1];
    $prereq{ $cryptmod[$id-1]->[1] } = '0';
}

my %todo;
while (my($k, $v) = each %prereq) {
    $todo{$k} = $v unless have_mod($k, $v);
}

if (%todo) {
    #unless (CPAN::Shell->can('install')) {
        print <<MSG;
Net::SSH::Perl depends on several external modules for
functionality. These modules can be installed
automatically for you, if you don't have them already;
to do so will require loading the CPAN shell, which may
require you to be running as root. If you'd rather not
install these modules, answer "n" to the following
questions. Note, however, that you'll still need to
install these modules manually to use Net::SSH::Perl.

MSG
    #}

    require Cwd;
    my $cwd = Cwd::cwd();
    while (my($k, $v) = each %todo) {
        if (prompt(sprintf("%s%s not installed/out of date. Install (y/n)?",
          $k, $v ? " (ver. $v)" : ""), "y") =~ /^y/) {
            require CPAN; CPAN::Shell->install($k);
            delete $prereq{$k};
            chdir $cwd or die "Can't chdir back to $cwd: $!";
        }
    }
}

WriteMakefile(
    NAME => 'Net::SSH::Perl',
    DISTNAME => 'Net-SSH-Perl',
    VERSION_FROM => 'lib/Net/SSH/Perl.pm',
    PREREQ_PM    => \%prereq,
    AUTHOR => 'Benjamin Trott <ben@rhumba.pair.com>',
    ABSTRACT => 'Perl client Interface to SSH',
);

sub have_mod {
    my($name, $ver) = @_;
    eval("use $name" . ($ver ? " $ver;" : ";"));
    !$@;
}
