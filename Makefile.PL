# $Id: Makefile.PL,v 1.9 2001/02/22 00:08:43 btrott Exp $

use ExtUtils::MakeMaker qw(prompt WriteMakefile);
use strict;

my %prereq = (
    'String::CRC32' => '1.2',
    'Math::GMP'     => '1.04',
    'Digest::MD5'   => '0',
);

my @cryptmod = (
    [ 'IDEA', 'Crypt::IDEA' ],
    [ 'DES', 'Crypt::DES' ],
    [ 'DES3', 'Crypt::DES' ],
    [ 'Blowfish', 'Crypt::Blowfish' ],
);

print<<MSG;

Each of the Net::SSH::Perl ciphers depend on a Crypt:: module
from CPAN. You may already have the necessary modules
installed, in which case you don't need to bother with
this step. Otherwise you'll need to install at least one
cipher to use Net::SSH::Perl. Please choose one from the
following list (Crypt::IDEA is the default).

MSG
my $i = 1;
for my $ciph (sort @cryptmod) {
    printf "    [%d] %s\n", $i++, $ciph->[0];
}
my $c = prompt("\nEnter your choices, separated by spaces:", 1);
print "\n";

for my $id (split /\s+/, $c) {
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
    AUTHOR => 'Benjamin Trott <btrott@ignitiondesign.com>',
    ABSTRACT => 'Perl client Interface to SSH',
);

sub have_mod {
    my($name, $ver) = @_;
    eval("use $name" . ($ver ? " $ver;" : ";"));
    !$@;
}
