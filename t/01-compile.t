my $loaded;
BEGIN { print "1..1\n" }
use Net::SSH::Perl;
$loaded++;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded }
