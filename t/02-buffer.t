# $Id: 02-buffer.t,v 1.4 2001/02/22 00:12:55 btrott Exp $

use strict;

use Test;
BEGIN { plan tests => 6 }

use Net::SSH::Perl::Buffer;

my $buffer = Net::SSH::Perl::Buffer->new;
ok($buffer);
$buffer->put_str("foo");
ok($buffer->get_str, "foo");

$buffer->put_str(0);
ok($buffer->get_str, 0);

$buffer->put_int32(999999999);
ok($buffer->get_int32, 999999999);

$buffer->put_char(pack "c", 2);
ok(unpack("c", $buffer->get_char), 2);

my $gmp = Math::GMP->new("999999999999999999999999999999");
$buffer->put_mp_int($gmp);
my $tmp = $buffer->get_mp_int;
ok("$tmp", "$gmp");
