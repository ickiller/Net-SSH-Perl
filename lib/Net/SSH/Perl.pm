# $Id: Perl.pm,v 1.24 2001/02/26 17:36:47 btrott Exp $

package Net::SSH::Perl;
use strict;

use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Config;
use Net::SSH::Perl::Constants qw/:msg :hosts PROTOCOL_MAJOR PROTOCOL_MINOR/;
use Net::SSH::Perl::Cipher;
use Net::SSH::Perl::Auth;
use Net::SSH::Perl::Util qw/:hosts _compute_session_id _rsa_public_encrypt/;
use Carp qw/croak/;

use vars qw/$VERSION/;
use Socket;
use Symbol;
use Math::GMP;

$VERSION = "0.53";

sub new {
    my $class = shift;
    my $host = shift;
    croak "usage: ", __PACKAGE__, "->new(\$host)"
        unless defined $host;
    my $ssh = bless { host => $host }, $class;
    $ssh->_init(@_);
    $ssh->debug(sprintf "Net::SSH Version $VERSION, protocol version %s.%s.",
        PROTOCOL_MAJOR, PROTOCOL_MINOR);
    $ssh;
}

sub _init {
    my $ssh = shift;
    my %arg = @_;
    my $user_config = delete $arg{user_config} || "$ENV{HOME}/.ssh/config";
    my $sys_config  = delete $arg{sys_config}  || "/etc/ssh_config";

    my $cfg = Net::SSH::Perl::Config->new($ssh->{host}, %arg);
    $ssh->{config} = $cfg;

    $ssh->debug("Reading configuration data $user_config");
    $cfg->read_config($user_config);
    $ssh->debug("Reading configuration data $sys_config");
    $cfg->read_config($sys_config);

    if (my $real_host = $ssh->{config}->get('hostname')) {
        $ssh->{host} = $real_host;
    }

    if (my $ciph = $ssh->{config}->get('cipher')) {
        my $cid;
        unless ($cid = Net::SSH::Perl::Cipher::id($ciph)) {
            croak "Cipher '$ciph' is unknown.";
        }
        unless (Net::SSH::Perl::Cipher::supported($cid)) {
            croak "Cipher '$ciph' is not supported.";
        }
    }

    if (scalar getpwuid($<) eq "root" &&
      !defined $ssh->{config}->get('privileged')) {
        $ssh->{config}->set('privileged', 1);
    }

    unless ($ssh->{config}->get('user_known_hosts')) {
        $ssh->{config}->set('user_known_hosts', "$ENV{HOME}/.ssh/known_hosts");
    }
    unless ($ssh->{config}->get('global_known_hosts')) {
        $ssh->{config}->set('global_known_hosts', "/etc/ssh_known_hosts");
    }
    unless (my $if = $ssh->{config}->get('identity_files')) {
        $ssh->{config}->set('identity_files', [ "$ENV{HOME}/.ssh/identity" ]);
    }

    # Turn on all auth methods we support unless otherwise instructed.
    # If the server doesn't support them they won't be tried anyway.
    for my $a (qw( password rhosts rhosts_rsa rsa )) {
        $ssh->{config}->set("auth_$a", 1)
            unless defined $ssh->{config}->get("auth_$a");
    }
}

sub config { $_[0]->{config} }

use vars qw/$CONFIG/;
$CONFIG = {};
sub configure {
    my $class = shift;
    $CONFIG = { @_ };
}

sub ssh {
    my($host, @cmd) = @_;
    my($user);
    ($host, $user) = $host =~ m!(.+)@(.+)! ?
       ($2, $1) : ($host, scalar getpwuid($<));
    my $ssh = __PACKAGE__->new($host, %$CONFIG);
    $ssh->login($user);
    my($out, $err, $exit) = $ssh->cmd(join ' ', @cmd);
    print $out;
    print STDERR $err if $err;
}

sub issh {
    my($host, @cmd) = @_;
    print join(' ', @cmd), "\n";
    print "Proceed: [y/N]:";
    my $x = scalar(<STDIN>);
    if ($x =~ /^y/i) {
        $CONFIG->{interactive} = 1;
        ssh($host, @cmd);
    }
}

sub _connect {
    my $ssh = shift;
    my $sock = $ssh->_create_socket;

    my $raddr = inet_aton($ssh->{host});
    croak "Net::SSH: Bad host name: $ssh->{host}"
        unless defined $raddr;
    my $rport = $ssh->{config}->get('port') || 'ssh';
    if ($rport =~ /\D/) {
        my @serv = getservbyname($rport, 'tcp');
        $rport = $serv[2];
    }
    $ssh->debug("Connecting to $ssh->{host}, port $rport.");
    connect($sock, sockaddr_in($rport, $raddr))
        or die "Can't connect to $ssh->{host}, port $rport: $!";

    select((select($sock), $|=1)[0]);

    $ssh->{session}{sock} = $sock;
    $ssh->_exchange_identification;

    $ssh->debug("Connection established.");
}

sub _create_socket {
    my $ssh = shift;
    my $sock = gensym;
    if ($ssh->{config}->get('privileged')) {
        my $p;
        my $proto = getprotobyname('tcp');
        for ($p = 1023; $p > 512; $p--) {
            socket($sock, AF_INET, SOCK_STREAM, $proto) ||
                croak "Net::SSH: Can't create socket: $!";
            last if bind($sock, sockaddr_in($p, INADDR_ANY));
            if ($! =~ /Address already in use/i) {
                close($sock);
                next;
            }
            croak "Net::SSH: Can't bind socket to port $p: $!";
        }
        $ssh->debug("Allocated local port $p.");
        $ssh->{config}->set('localport', $p);
    }
    else {
        socket($sock, AF_INET, SOCK_STREAM, 0) ||
            croak "Net::SSH: Can't create socket: $!";
    }
    $sock;
}

sub _disconnect {
    my $ssh = shift;
    my $packet = $ssh->packet_start(SSH_MSG_DISCONNECT);
    $packet->put_str("@_") if @_;
    $packet->send;
    $ssh->{session} = {};
}

sub fatal_disconnect {
    my $ssh = shift;
    $ssh->_disconnect(@_);
    croak @_;
}

sub sock {
    unless ($_[0]->{session}{sock}) {
        croak "Not connected!";
    }
    $_[0]->{session}{sock};
}

sub _exchange_identification {
    my $ssh = shift;
    my $sock = $ssh->{session}{sock};
    my $remote_id = <$sock>;
    my($remote_major, $remote_minor, $remote_version) = $remote_id =~
        /^SSH-(\d+)\.(\d+)-([^\n]+)\n$/;
    $ssh->debug("Remote protocol version $remote_major.$remote_minor, remote software version $remote_version");
    printf $sock "SSH-%d.%d-%s\n",
        PROTOCOL_MAJOR, PROTOCOL_MINOR, $VERSION;
}

sub debug {
    my $ssh = shift;
    print STDERR "@_\n" if $ssh->{config}->get('debug');
}

sub login {
    my $ssh = shift;
    my($user, $pass) = @_;
    $pass = $CONFIG->{ssh_password} if exists $CONFIG->{ssh_password};
    $user = scalar getpwuid($<) unless defined $user;
    $ssh->{config}->set('user', $user);
    $ssh->{config}->set('pass', $pass);
}

sub _login {
    my $ssh = shift;
    my $user = $ssh->{config}->get('user');
    croak "No user defined" unless $user;

    $ssh->debug("Waiting for server public key.");
    my $packet = Net::SSH::Perl::Packet->read_expect($ssh, SSH_SMSG_PUBLIC_KEY);

    my $data = $packet->data;
    my $check_bytes = $data->bytes(0, 8, "");

    my %keys;
    for my $which (qw/public host/) {
        $keys{$which}{bits} = $data->get_int32;
        $keys{$which}{e}    = $data->get_mp_int;
        $keys{$which}{n}    = $data->get_mp_int;
    }

    my $protocol_flags = $data->get_int32;
    my $supported_ciphers = $data->get_int32;
    my $supported_auth = $data->get_int32;

    $ssh->debug(sprintf "Received server public key (%d bits) and " .
        "host key (%d bits).", $keys{public}{bits}, $keys{host}{bits});

    my $session_id =
      _compute_session_id($check_bytes, $keys{host}, $keys{public});
    $ssh->{session}{id} = $session_id;

    my $status =
      _check_host_in_hostfile($ssh->{host},
      $ssh->{config}->get('user_known_hosts'), $keys{host});

    unless (defined $status && $status == HOST_OK) {
        $status =
          _check_host_in_hostfile($ssh->{host},
          $ssh->{config}->get('global_known_hosts'), $keys{host});
    }

    if ($status == HOST_OK) {
        $ssh->debug(sprintf "Host '%s' is known and matches the host key.",
            $ssh->{host});
    }
    elsif ($status == HOST_NEW) {
        $ssh->debug(sprintf "Host key for host '%s' not found from the list " .
            "of known hosts... adding.", $ssh->{host});
        _add_host_to_hostfile($ssh->{host},
            $ssh->{config}->get('user_known_hosts'), $keys{host});
    }
    else {
        croak sprintf "Host key for '%s' has changed!", $ssh->{host};
    }

    my $session_key = join '', map chr rand(255), 0..31;

    my $skey = Math::GMP->new(0);
    for my $i (0..31) {
        $skey = Math::GMP::mul_2exp_gmp($skey, 8);
        if ($i < 16) {
            Math::GMP::add_ui_gmp($skey,
                ord(substr($session_key, $i, 1) ^ substr($session_id, $i, 1)));
        }
        else {
            Math::GMP::add_ui_gmp($skey, ord(substr($session_key, $i, 1)));
        }
    }

    if (Math::GMP::cmp_two($keys{public}{n}, $keys{host}{n}) < 0) {
        $skey = _rsa_public_encrypt($skey, $keys{public});
        $skey = _rsa_public_encrypt($skey, $keys{host});
    }
    else {
        $skey = _rsa_public_encrypt($skey, $keys{host});
        $skey = _rsa_public_encrypt($skey, $keys{public});
    }

    my($cipher, $cipher_name);
    if ($cipher_name = $ssh->{config}->get('cipher')) {
        $cipher = Net::SSH::Perl::Cipher::id($cipher_name);
    }
    else {
        my $cid;
        if (($cid = Net::SSH::Perl::Cipher::id('IDEA')) &&
            Net::SSH::Perl::Cipher::supported($cid, $supported_ciphers)) {
            $cipher_name = 'IDEA';
            $cipher = $cid;
        }
    }

    unless (Net::SSH::Perl::Cipher::supported($cipher, $supported_ciphers)) {
        croak sprintf "Selected cipher type %s not supported by server.",
            $cipher_name;
    }
    $ssh->debug(sprintf "Encryption type: %s", $cipher_name);

    $packet = $ssh->packet_start(SSH_CMSG_SESSION_KEY);
    $packet->put_int8($cipher);
    $packet->put_char($_) for split //, $check_bytes;
    $packet->put_mp_int($skey);
    $packet->put_int32(0);    ## No protocol flags.
    $packet->send;
    $ssh->debug("Sent encrypted session key.");

    $ssh->set_cipher($cipher_name, $session_key);
    $ssh->{session}{key} = $session_key;

    Net::SSH::Perl::Packet->read_expect($ssh, SSH_SMSG_SUCCESS);
    $ssh->debug("Received encryption confirmation.");

    $packet = $ssh->packet_start(SSH_CMSG_USER);
    $packet->put_str($user);
    $packet->send;

    $packet = Net::SSH::Perl::Packet->read($ssh);
    return 1 if $packet->type == SSH_SMSG_SUCCESS;

    if ($packet->type != SSH_SMSG_FAILURE) {
        $ssh->fatal_disconnect(sprintf
          "Protocol error: got %d in response to SSH_CMSG_USER", $packet->type);
    }

    my $auth_order = Net::SSH::Perl::Auth::auth_order();
    for my $auth_id (@$auth_order) {
        next unless Net::SSH::Perl::Auth::supported($auth_id, $supported_auth);
        my $auth = Net::SSH::Perl::Auth->new(Net::SSH::Perl::Auth::name($auth_id), $ssh);
        my $valid = $auth->authenticate;
        return 1 if $valid;
    }
}

sub cmd {
    my $ssh = shift;
    my $cmd = shift;
    my $stdin = shift;

    $ssh->_connect;
    $ssh->fatal_disconnect("Permission denied") unless $ssh->_login;

    my($packet);

    $ssh->debug("Sending command: $cmd");
    $packet = $ssh->packet_start(SSH_CMSG_EXEC_CMD);
    $packet->put_str($cmd);
    $packet->send;

    $ssh->debug("Entering interactive session.");

    if (defined $stdin) {
        $packet = $ssh->packet_start(SSH_CMSG_STDIN_DATA);
        $packet->put_str($stdin);
        $packet->send;

        $packet = $ssh->packet_start(SSH_CMSG_EOF);
        $packet->send;
    }

    my($stdout, $stderr, $exit);
    my $h = {};
    $h->{+SSH_SMSG_STDOUT_DATA} ||= sub { $stdout .= $_[1]->get_str };
    $h->{+SSH_SMSG_STDERR_DATA} ||= sub { $stderr .= $_[1]->get_str };
    $h->{+SSH_SMSG_EXITSTATUS}  ||= sub { $exit    = $_[1]->get_int32 };

    while (1) {
        my $pack = Net::SSH::Perl::Packet->read($ssh);
        if (!defined $pack) {
            sleep 2;
            redo;
        }

        if (my $code = $h->{ $pack->type }) {
            $code->($ssh, $pack);
        }
        else {
            $ssh->fatal_disconnect(sprintf
                "Didn't expect packet of type %d; buffer is %s\n",
                $pack->type, $pack->bytes);
        }

        last if $pack->type == SSH_SMSG_EXITSTATUS;
    }

    $packet = $ssh->packet_start(SSH_CMSG_EXIT_CONFIRMATION);
    $packet->send;

    $ssh->_disconnect;

    ($stdout, $stderr, $exit);
}

sub in_leftover {
    my $ssh = shift;
    if (@_) {
        $ssh->{session}{in_leftover} = shift;
    }
    $ssh->{session}{in_leftover};
}

sub set_cipher {
    my $ssh = shift;
    my $ciph = shift;
    $ssh->{session}{receive} = Net::SSH::Perl::Cipher->new($ciph, @_);
    $ssh->{session}{send} = Net::SSH::Perl::Cipher->new($ciph, @_);
}

sub send_cipher { $_[0]->{session}{send} }
sub receive_cipher { $_[0]->{session}{receive} }
sub session_key { $_[0]->{session}{key} }
sub session_id { $_[0]->{session}{id} }

sub packet_start { Net::SSH::Perl::Packet->new($_[0], type => $_[1]) }

1;
__END__

=head1 NAME

Net::SSH::Perl - Perl client Interface to SSH

=head1 SYNOPSIS

    use Net::SSH::Perl;
    my $ssh = Net::SSH::Perl->new($host);
    $ssh->login($user, $pass);
    my($stdout, $stderr, $exit) = $ssh->cmd($cmd);

=head1 DESCRIPTION

I<Net::SSH::Perl> is an all-Perl module implementing an ssh client.
It enables you to simply and securely execute commands on remote
machines, and receive the STDOUT, STDERR, and exit status of that
remote command.

It contains built-in support for various methods of authenticating
with the server (password authentication, RSA challenge-response
authentication, etc.). It completely implements the I/O buffering,
packet transport, and user authentication layers of the SSH protocol,
and makes use of external Perl libraries (in the Crypt:: family of
modules) to handle encryption of all data sent across the insecure
network. It can also read your existing SSH configuration files
(F</etc/ssh_config>, etc.), RSA identity files, known hosts files,
etc.

One advantage to using I<Net::SSH::Perl> over wrapper-style
implementations of ssh clients is that it saves on process
overhead: you no longer need to fork and execute a separate process
in order to connect to an sshd. Depending on the amount of time
and memory needed to fork a process, this win can be quite
substantial; particularly if you're running in a persistent
Perl environment (I<mod_perl>, for example), where forking a new
process is a drain on process and memory resources.

It also simplifies the process of using password-based authentications;
when writing a wrapper around I<ssh> you probably need to use
I<Expect> to control the ssh client and give it your password.
I<Net::SSH::Perl> has built-in support for the authentication
protocols, so there's no longer any hassle of communicating with
any external processes.

=head1 BASIC USAGE

Usage of I<Net::SSH::Perl> is very simple.

=head2 Net::SSH::Perl->new($host, %params)

To set up a new connection, call the I<new> method, which
connects to I<$host> and returns a I<Net::SSH::Perl> object.

I<new> accepts the following named parameters in I<%params>:

=over 4

=item * cipher

Specifies the name of the encryption cipher that you wish to
use for this connection. This must be one of the supported
ciphers (currently, I<IDEA>, I<DES>, I<DES3>, and I<Blowfish>);
specifying an unsupported cipher is a fatal error. The default
cipher is I<IDEA>.

=item * port

The port of the I<sshd> daemon to which you wish to connect;
if not specified, this is assumed to be the default I<ssh>
port.

=item * debug

Set to a true value if you want debugging messages printed
out while the connection is being opened. These can be helpful
in trying to determine connection problems, etc. The messages
are similar (and in some cases exact) to those written out by
the I<ssh> client when you use the I<-v> option.

Defaults to false.

=item * interactive

Set to a true value if you're using I<Net::SSH> interactively.
This is used in determining whether or not to display password
prompts, for example. It's basically the inverse of the
I<BatchMode> parameter in ssh configuration.

Defaults to false.

=item * privileged

Set to a true value if you want to bind to a privileged port
locally. You'll need this if you plan to use Rhosts or
Rhosts-RSA authentication, because the remote server
requires the client to connect on a privileged port. Of course,
to bind to a privileged port you'll need to be root.

If you don't provide this parameter, and I<Net::SSH::Perl>
detects that you're running as root, this will automatically
be set to true. Otherwise it defaults to false.

=item * identity_files

A list of RSA identity files to be used in RSA authentication.
The value of this argument should be a reference to an array of
strings, each string identifying the location of an identity
file.

If you don't provide this, RSA authentication defaults to using
"$ENV{HOME}/.ssh/identity".

=back

=head2 $ssh->login([ $user [, $password ] ])

Sets the username and password to be used when authenticating
with the I<sshd> daemon. The username I<$user> is required for
all authentication protocols (to identify yourself to the
remote server), but if you don't supply it the username of the
user executing the program is used.

The password I<$password> is needed only for password
authentication (it's not used for RSA passphrase authentication,
though perhaps it should be). And if you're running in an
interactive session and you've not provided a password, you'll
be prompted for one.

=head2 ($out, $err, $exit) = $ssh->cmd($cmd, [ $stdin ])

Runs the command I<$cmd> on the remote server and returns
the I<stdout>, I<stderr>, and exit status of that
command.

If I<$stdin> is provided, it's supplied to the remote command
I<$cmd> on standard input.

NOTE: the ssh protocol does not support (so far as I know)
running multiple commands per connection, unless those
commands are chained together so that the remote shell
can evaluate them. Because of this, a new socket connection
is created each time you call I<cmd>, and disposed of
afterwards. In other words, this code:

    my $ssh = Net::SSH::Perl->new("host1");
    $ssh->login("user1", "pass1");

    $ssh->cmd("foo");
    $ssh->cmd("bar");

will actually connect to the I<sshd> on the first
invocation of I<cmd>, then disconnect; then connect
again on the second invocation of I<cmd>, then disconnect
again.

This is less than ideal, obviously. Future version of
I<Net::SSH::Perl> may find ways around that.

=head1 ADVANCED METHODS

Your basic SSH needs will hopefully be met by the methods listed
above. If they're not, however, you may want to use some of the
additional methods listed here. Some of these are aimed at
end-users, while others are probably more useful for actually
writing an authentication module, or a cipher, etc.

=head2 $ssh->config

Returns the I<Net::SSH::Perl::Config> object managing the
configuration data for this SSH object. This is constructed
from data passed in to the constructor I<new> (see above),
merged with data read from the user and system configuration
files. See the I<Net::SSH::Perl::Config> docs for details
on methods you can call on this object (you'll probably
be more interested in the I<get> and I<set> methods).

=head2 $ssh->sock

Returns the socket connection to sshd. If your client is not
connected, dies.

=head2 $ssh->debug($msg)

If debugging is turned on for this session (see the I<debug>
parameter to the I<new> method, above), writes I<$msg> to
C<STDERR>. Otherwise nothing is done.

=head2 $ssh->in_leftover([ $leftover ])

"Input leftover"; you can use this to store the data left over
from the last socket read, the data that wasn't read into a
packet on the client side. This is needed because we read as
much data as we can (up to 8192) from the remote socket; not all
of the data we read comprises one single packet, however. Your
client code, though, will most likely have asked for one
single packet; so we need some way to store the leftover data
between reads.

If passed I<$leftover>, sets the internal leftover buffer.

Returns the contents of the leftover buffer.

=head2 $ssh->set_cipher($cipher_name)

Sets the cipher for the SSH session I<$ssh> to I<$cipher_name>
(which must be a valid cipher name), and turns on encryption
for that session.

=head2 $ssh->send_cipher

Returns the "send" cipher object. This is the object that encrypts
outgoing data.

If it's not defined, encryption is not turned on for the session.

=head2 $ssh->receive_cipher

Returns the "receive" cipher object. This is the object that
decrypts incoming data.

If it's not defined, encryption is not turned on for the session.

NOTE: the send and receive ciphers and two I<different> objects,
each with its own internal state (initialization vector, in
particular). Thus they cannot be interchanged.

=head2 $ssh->session_key

Returns the session key, which is simply 32 bytes of random
data and is used as the encryption/decryption key.

=head2 $ssh->session_id

Returns the session ID, which is generated from the server's
host and server keys, and from the check bytes that it sends
along with the keys. The server may require the session ID to
be passed along in other packets, as well (for example, when
responding to RSA challenges).

=head2 $packet = $ssh->packet_start($packet_type)

Starts building a new packet of type I<$packet_type>. This is
just a handy method for lazy people. Internally it calls
I<Net::SSH::Perl::Packet::new>, so take a look at those docs
for more details.

=head1 SUPPORT

For samples/tutorials, take a look at the scripts in F<eg/> in
the distribution directory.

If you have any questions, code samples, bug reports, or
feedback, please email them to:

    ben@rhumba.pair.com

=head1 AUTHOR & COPYRIGHT

Benjamin Trott, ben@rhumba.pair.com

Except where otherwise noted, Net::SSH::Perl is Copyright
2001 Benjamin Trott. All rights reserved. Net::SSH::Perl is
free software; you may redistribute it and/or modify it under
the same terms as Perl itself.

=cut
