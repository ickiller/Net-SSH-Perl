#
# Parts copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#

package Net::SSH::Perl::Cipher::CBC;
use strict;

use Carp qw/croak/;

sub new {
    my($class, $ciph) = @_;
    bless {
        cipher => $ciph,
        iv     => "\0" x $ciph->blocksize,
    }, $class;
}

sub encrypt {
    my $cbc = shift;
    my $data = shift;

    my $retval = "";
    my $iv = $cbc->{iv};
    my $size = $cbc->{cipher}->blocksize;

    while (length $data) {
        my $in = substr($data, 0, $size, '') ^ $iv;
        $iv = $cbc->{cipher}->encrypt($in);
	$retval .= $iv;
    }

    $cbc->{iv} = $iv;
    $retval;
}

sub decrypt {
    my $cbc = shift;
    my $data = shift;

    my $retval = "";
    my $iv = $cbc->{iv};
    my $size = $cbc->{cipher}->blocksize;

    while (length $data) {
        my $in = substr($data, 0, $size, '');
        $retval .= $cbc->{cipher}->decrypt($in) ^ $iv;
        $iv = $in;
    }

    $cbc->{iv} = $iv;
    $retval;
}

1;
