use strict;

use vars qw( $CFG_FILE );
BEGIN { unshift @INC, 't/' }
require 'test-common.pl';

use Net::SSH::Perl;
use Net::SSH::Perl::Config;

use Test;
BEGIN { plan tests => 23 };

my($cfg, $ssh);

$cfg = Net::SSH::Perl::Config->new("foo");
ok($cfg);
$cfg->read_config($CFG_FILE);

## Test get/set methods on port/Port directive.
ok($cfg->get('port'), 10000);
$cfg->set('port', 5000);
ok($cfg->get('port'), 5000);

## Test identity file special case.
my $if = $cfg->get('identity_files');
ok($if && UNIVERSAL::isa($if, 'ARRAY'));
ok(scalar @$if, 2);
ok($if->[0], 'identity');
ok($if->[1], 'identity2');

## Test whether options given in constructor override config file.
$cfg = Net::SSH::Perl::Config->new("foo", port => 22);
ok($cfg);
$cfg->read_config($CFG_FILE);
ok($cfg->get('port'), 22);

## Test whether we can use merge_directive to merge in a directive
## in a string.
$cfg->merge_directive("RhostsAuthentication no");
ok($cfg->get('auth_rhosts'), 0);

## Test grabbing a different Host record from the config file.
$cfg = Net::SSH::Perl::Config->new("dummy");
ok($cfg);
ok($cfg->{host}, "dummy");
$cfg->read_config($CFG_FILE);
ok($cfg->get('port'), 5000);
ok($cfg->get('interactive'), 1);

## Test that config file gets read correctly when passed to
## Net::SSH::Perl constructor.
$ssh = Net::SSH::Perl->new("foo", user_config => $CFG_FILE);
ok($ssh);
ok($ssh->config);
ok($ssh->config->get('port'), 10000);

## Test that Net::SSH::Perl uses the HostName directive to
## override the host passed to the constructor.
ok($ssh->config->get('hostname'), 'foo.bar.com');
ok($ssh->{host}, 'foo.bar.com');

## And that constructor overrides work here, as well.
$ssh = Net::SSH::Perl->new("foo", user_config => $CFG_FILE, port => 22);
ok($ssh->config->get('port'), 22);

## And now test whether we can set additional options through
## Net::SSH::Perl constructor; and that they override config
## file.
$ssh = Net::SSH::Perl->new("foo", user_config => $CFG_FILE, options => [
    "Port 22", "RhostsAuthentication no", "BatchMode no" ]);
ok($ssh->config->get('port'), 22);
ok($ssh->config->get('auth_rhosts'), 0);
ok($ssh->config->get('interactive'), 1);
