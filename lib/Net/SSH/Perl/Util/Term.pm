# $Id: Term.pm,v 1.3 2001/04/17 06:16:15 btrott Exp $

package Net::SSH::Perl::Util::Term;
use strict;

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

sub _read_yes_or_no {
    my($prompt, $def) = @_;
    print $prompt, " [$def] ";
    chomp(my $ans = <STDIN>);
    $ans = $def unless $ans;
    $ans =~ /^y/i;
}

1;
