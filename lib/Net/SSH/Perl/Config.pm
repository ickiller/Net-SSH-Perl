# $Id: Config.pm,v 1.4 2001/02/28 22:14:06 btrott Exp $

package Net::SSH::Perl::Config;
use strict;

use vars qw( %DIRECTIVES );

%DIRECTIVES = (
    Host                    => [ \&_host ],
    BatchMode               => [ \&_batch_mode ],
    Cipher                  => [ \&_set_str, 'cipher' ],
    GlobalKnownHostsFile    => [ \&_set_str, 'global_known_hosts' ],
    HostName                => [ \&_set_str, 'hostname' ],
    IdentityFile            => [ \&_identity_file ],
    PasswordAuthentication  => [ \&_set_yesno, 'auth_password' ],
    PasswordPromptHost      => [ \&_set_yesno, 'password_prompt_host' ],
    PasswordPromptLogin     => [ \&_set_yesno, 'password_prompt_login' ],
    Port                    => [ \&_set_str, 'port' ],
    RhostsAuthentication    => [ \&_set_yesno, 'auth_rhosts' ],
    RhostsRSAAuthentication => [ \&_set_yesno, 'auth_rhosts_rsa' ],
    RSAAuthentication       => [ \&_set_yesno, 'auth_rsa' ],
    UsePrivilegedPort       => [ \&_set_yesno, 'privileged' ],
    User                    => [ \&_set_str, 'user' ],
    UserKnownHostsFile      => [ \&_set_str, 'user_known_hosts' ],
);

sub new {
    my $class = shift;
    my $host  = shift;
    bless { host => $host, o => { @_ } }, $class;
}

sub get { $_[0]->{o}{ $_[1] } }

sub set {
    my($cfg, $key) = @_;
    $cfg->{o}{$key} = $_[2] if @_ == 3;
    $cfg->{o}{$key};
}

sub read_config {
    my($cfg, $conf_file) = @_;

    local $cfg->{_state} = { host => $cfg->{host}, host_matched => 1 };

    local($_, $/, *FH);
    $/ = "\n";
    open FH, $conf_file or return;
    while (<FH>) {
        next if !/\S/ || /^#/;
        my($key, $args) = $_ =~ /^\s*(\S+)\s+(.+)$/;
        next unless $key && $args;
        next unless $cfg->{_state}{host_matched} || $key eq "Host";

        my $code = $DIRECTIVES{$key}[0] or next;
        $code->($cfg, $key, $args);
    }
    close FH;
}

sub _host {
    my($cfg, $key, $host) = @_;
    if ($host ne '*' && $cfg->{_state}{host} !~ /$host/) {
        $cfg->{_state}{host_matched} = 0;
    }
    else {
        $cfg->{_state}{host_matched} = 1;
    }
}

sub _batch_mode {
    my($cfg, $key, $batch) = @_;
    $cfg->{o}{interactive} = $batch eq "yes" ? 0 : 1;
}

sub _identity_file {
    my($cfg, $key, $id_file) = @_;
    $cfg->{identity_files} = []
        unless ref $cfg->{o}{identity_files} eq "ARRAY";
    push @{ $cfg->{o}{identity_files} }, $id_file;
}

sub _set_str {
    my($cfg, $key, $value) = @_;
    return if exists $cfg->{o}{ $DIRECTIVES{$key}[1] };
    $cfg->{o}{ $DIRECTIVES{$key}[1] } = $value;
}

sub _set_yesno {
    my($cfg, $key, $yesno) = @_;
    return if exists $cfg->{o}{ $DIRECTIVES{$key}[1] };
    if ($yesno eq "yes") {
        $cfg->{o}{ $DIRECTIVES{$key}[1] } = 1;
    }
    elsif ($yesno eq "no") {
        $cfg->{o}{ $DIRECTIVES{$key}[1] } = 0;
    }
    else {
        warn "Configuration setting for '$key' must be 'yes' or 'no'";
    }
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Config - Load and manage SSH configuration

=head1 SYNOPSIS

    use Net::SSH::Perl::Config;
    my $cfg = Net::SSH::Perl::Config->new($host, foo => 'bar');
    $cfg->read_config($config_file);
    my $v = $cfg->get('foo');

=head1 DESCRIPTION

I<Net::SSH::Perl::Config> manages configuration data for
I<Net::SSH::Perl>. It merges options handed to it at object
construction with options read from configuration files.
Just as in the actual ssh program, the first obtained value
of a configuration parameter is the value that's used; in
other words, values given in the original parameter list will
always override values read from configuration files.

The configuration files should be in the same format used
for the ssh command line program; see the I<ssh> manpage
for information on this format. I<Net::SSH::Perl::Config>
understands a subset of the configuration directives that
can live in these files; this subset matches up with the
functionality that I<Net::SSH::Perl> can support. Unknown
keywords will simply be skipped.

=head1 USAGE

=head2 Net::SSH::Perl::Config->new($host, %args)

Constructs a new configuration container object and returns
that object. I<$host> is the host to which you're applying
this configuration; you can leave it out (pass in an
undefined or empty argument) if it's not applicable to you.

I<$host> is needed for parsing the host-specific sections
of the configuration files; the I<Host> keyword restricts
a set of directives as applying to a particular host (or
set of hosts). When it encounters such a section,
I<Net::SSH::Perl::Config> will skip all of the directives
in the section unless the host matches I<$host>.

I<%args> can contain the same arguments that you can pass
to the I<new> method of I<Net::SSH::Perl>--those arguments
are eventually passed through to this method when setting
up the SSH object. The elements in I<%args> override values
in the configuration files.

=head2 $cfg->read_config($file)

Reads in the configuration file I<$file> and adds any
appropriate configuration data to the settings maintained
by the I<$cfg> object. If I<$file> is unreadable, simply
returns quietly.

As stated above, values read from the configuration files
are overriden by those passed in to the constructor.
Furthermore, if you're reading from several config files
in sequence, values read from the first files will override
those read from the second, third, fourth, etc. files.

=head2 $cfg->get($key)

Returns the value of the configuration parameter I<$key>,
and undefined if that parameter has not been set.

=head2 $cfg->set($key, $value)

Sets the value of the parameter I<$key> to I<$value>, and
returns the new value.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
