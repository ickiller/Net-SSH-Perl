#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#

package Net::SSH::Perl::Cipher::CFB;
use strict;

use Carp qw/croak/;

sub new {
    my($class, $ciph) = @_;
    my $cfb = bless {
        cipher    => $ciph,
        iv        => "\0" x $ciph->blocksize,
    }, $class;
}

sub encrypt {
    my $cfb = shift;
    my $data = shift;
    croak "Data length must be a multiple of 8"
        if length($data) % 8;

    my $retval = "";
    my $iv = $cfb->{iv};
    my $size = $cfb->{cipher}->blocksize;

    while (length $data) {
        my $out = $cfb->{cipher}->encrypt($iv);
        $iv = substr($data, 0, $size, '') ^ substr($out, 0, $size, '');
        $retval .= $iv;
    }

    $cfb->{iv} = $iv;
    $retval;
}

sub decrypt {
    my $cfb = shift;
    my $data = shift;
    croak "Data length must be a multiple of 8"
        if length($data) % 8;

    my $retval = "";
    my $iv = $cfb->{iv};
    my $size = $cfb->{cipher}->blocksize;

    while (length $data) {
        my $out = $cfb->{cipher}->encrypt($iv);
        $iv = substr($data, 0, $size, '');
        $retval .= $iv ^ substr($out, 0, $size);
    }

    $cfb->{iv} = $iv;
    $retval;
}

1;
