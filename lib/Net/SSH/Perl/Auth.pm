package Net::SSH::Perl::Auth;

use strict;
use Carp qw/croak/;

use vars qw/%AUTH %AUTH_REVERSE @AUTH_ORDER %SUPPORTED/;
BEGIN {
    %AUTH = (
        Rhosts       => 1,
        RSA          => 2,
        Password     => 3,
        Rhosts_RSA   => 4,
        TIS          => 5,
        Kerberos     => 6,
        Kerberos_TGT => 7,
    );
    %AUTH_REVERSE = reverse %AUTH;

    for my $auth (keys %AUTH) {
        my $pack = sprintf "%s::%s", __PACKAGE__, $auth;
        eval "use $pack";
        $SUPPORTED{$AUTH{$auth}}++ unless $@;
    }

    @AUTH_ORDER = qw/7 6 1 4 2 5 3/;
}

sub new {
    my $class = shift;
    my $type = shift;
    my $auth_class = join '::', __PACKAGE__, $type;
    (my $lib = $auth_class . ".pm") =~ s!::!/!g;
    require $lib;
    $auth_class->new(@_);
}

sub id {
    my $this = shift;
    my $type;
    if (my $class = ref $this) {
        my $pack = __PACKAGE__;
        ($type = $class) =~ s/^${pack}:://;
    }
    else {
        $type = $this;
    }
    $AUTH{$type};
}

sub name {
    my $this = shift;
    my $name;
    if (my $class = ref $this) {
        my $pack = __PACKAGE__;
        ($name = $class) =~ s/^${pack}:://;
    }
    else {
        $name = $AUTH_REVERSE{$this};
    }
    $name;
}

sub mask {
    my $mask = 0;
    $mask |= (1<<$_) for keys %SUPPORTED;
    $mask;
}

sub supported {
    return [ keys %SUPPORTED ] unless @_;
    my $id = shift;
    return $id == 0 || exists $SUPPORTED{$id} unless @_;
    my $ssupp = shift;
    mask() & $ssupp & (1 << $id);
}

sub auth_order { \@AUTH_ORDER }

sub authenticate { 0 }

1;
__END__

=head1 NAME

Net::SSH::Perl::Auth - Base authentication class, plus utility methods

=head1 SYNOPSIS

   use Net::SSH::Perl::Cipher;

   # Get list of supported authentication IDs.
   my $supported = Net::SSH::Perl::Auth::supported();

   # Translate an auth name into an ID.
   my $id = Net::SSH::Perl::Auth::id($name);

   # Translate an auth ID into a name.
   my $name = Net::SSH::Perl::Auth::name($id);

   # Get the order in which auth methods are tested.
   my $order = Net::SSH::Perl::Auth::order();

=head1 DESCRIPTION

I<Net::SSH::Perl::Auth> provides a base class for each of
the authentication method classes. In addition, it defines
a set of utility methods that can be called either as
functions or object methods.

=head1 AUTH DEVELOPMENT

Classes implementing an authentication method must implement
the following two methods:

=over 4

=item * $class->new($ssh)

Given a I<Net::SSH::Perl> object I<$ssh>, should construct a
new auth object and bless it into I<$class>, presumably.

=item * $class->authenticate()

Authenticate the current user with the remote daemon. This
requires following the messaging protocol defined for your
authentication method. All of the data you need--user name,
password (if required), etc.--should be in the I<$ssh>
object.

Returns 1 if the authentication is successful, 0 otherwise.

=head1 AUTHOR

Benjamin Trott, ben@rhumba.pair.com

=head1 COPYRIGHT

(C) 2001 Benjamin Trott. All rights reserved.

=cut
