# $Id: Perl.pm,v 1.50 2001/03/23 00:56:28 btrott Exp $

package Net::SSH::Perl;
use strict;

use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Buffer;
use Net::SSH::Perl::Config;
use Net::SSH::Perl::Constants qw( :msg :hosts PROTOCOL_MAJOR PROTOCOL_MINOR );
use Net::SSH::Perl::Cipher;
use Net::SSH::Perl::Auth;
use Net::SSH::Perl::Util qw( :hosts _compute_session_id _rsa_public_encrypt );

use vars qw( $VERSION $CONFIG $HOSTNAME );
$CONFIG = {};

use Socket;
use Fcntl;
use Symbol;
use Math::GMP;
use Carp qw( croak );
use Sys::Hostname;
eval {
    $HOSTNAME = hostname();
};

$VERSION = "0.66";

sub new {
    my $class = shift;
    my $host = shift;
    croak "usage: ", __PACKAGE__, "->new(\$host)"
        unless defined $host;
    my $ssh = bless { host => $host }, $class;
    $ssh->_init(@_);
    $ssh->debug($class->version_string);
    $ssh;
}

sub version_string {
    my $class = shift;
    sprintf "%s Version %s, protocol version %s.%s.",
        $class, $VERSION, PROTOCOL_MAJOR, PROTOCOL_MINOR;
}

sub _init {
    my $ssh = shift;
    my %arg = @_;
    my $user_config = delete $arg{user_config} || "$ENV{HOME}/.ssh/config";
    my $sys_config  = delete $arg{sys_config}  || "/etc/ssh_config";

    my $directives = delete $arg{options} || [];

    my $cfg = Net::SSH::Perl::Config->new($ssh->{host}, %arg);
    $ssh->{config} = $cfg;

    # Merge config-format directives given through "options"
    # (just like -o option to ssh command line). Do this before
    # reading config files so we override files.
    for my $d (@$directives) {
        $cfg->merge_directive($d);
    }

    for my $f (($user_config, $sys_config)) {
        $ssh->debug("Reading configuration data $f");
        $cfg->read_config($f);
    }

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

    unless (defined $ssh->{config}->get('password_prompt_login')) {
        $ssh->{config}->set('password_prompt_login', 1);
    }
    unless (defined $ssh->{config}->get('password_prompt_host')) {
        $ssh->{config}->set('password_prompt_host', 1);
    }

    # Turn on all auth methods we support unless otherwise instructed.
    # If the server doesn't support them they won't be tried anyway.
    for my $a (qw( password rhosts rhosts_rsa rsa )) {
        $ssh->{config}->set("auth_$a", 1)
            unless defined $ssh->{config}->get("auth_$a");
    }
}

sub config { $_[0]->{config} }

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
        my @serv = getservbyname(my $serv = $rport, 'tcp');
        $rport = $serv[2];
        croak "Can't map service name '$serv' to port number"
            unless defined $rport;
    }
    $ssh->debug("Connecting to $ssh->{host}, port $rport.");
    connect($sock, sockaddr_in($rport, $raddr))
        or die "Can't connect to $ssh->{host}, port $rport: $!";

    select((select($sock), $|=1)[0]);

    $ssh->{session}{sock} = $sock;
    $ssh->_exchange_identification;

    fcntl($sock, F_SETFL, O_NONBLOCK)
        or die "Can't set socket non-blocking: $!";

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
    for my $key (qw( _cmd_stdout _cmd_stderr _cmd_exit )) {
        $ssh->{$key} = "";
    }
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
    if ($ssh->{config}->get('debug')) {
        printf STDERR "%s@_\n", $HOSTNAME ? "$HOSTNAME: " : '';
    }
}

sub login {
    my $ssh = shift;
    my($user, $pass) = @_;
    if (!defined $ssh->{config}->get('user')) {
        $ssh->{config}->set('user',
            defined $user ? $user : scalar getpwuid($<));
    }
    if (!defined $pass && exists $CONFIG->{ssh_password}) {
        $pass = $CONFIG->{ssh_password};
    }
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
    for my $which (qw( public host )) {
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
        elsif (($cid = Net::SSH::Perl::Cipher::id('DES3')) &&
            Net::SSH::Perl::Cipher::supported($cid, $supported_ciphers)) {
            $cipher_name = 'DES3';
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

sub compression {
    my $ssh = shift;
    if (@_) {
        my $level = shift;
        $ssh->debug("Enabling compression at level $level.");
        $ssh->{session}{compression} = $level;

        my($err);
        ($ssh->{session}{send_compression}, $err) =
            Compress::Zlib::deflateInit({ Level => $level });
        $ssh->fatal_disconnect("Can't create outgoing compression stream")
            unless $err == Compress::Zlib::Z_OK();

        ($ssh->{session}{receive_compression}, $err) =
            Compress::Zlib::inflateInit();
        $ssh->fatal_disconnect("Can't create incoming compression stream")
            unless $err == Compress::Zlib::Z_OK();
    }
    $ssh->{session}{compression};
}

sub send_compression { $_[0]->{session}{send_compression} }
sub receive_compression { $_[0]->{session}{receive_compression} }

sub register_handler {
    my($ssh, $type, $sub, $force) = @_;
    if (!exists $ssh->{client_handlers}{$type} || $force) {
        $ssh->{client_handlers}{$type} = $sub;
    }
}

sub _setup_connection {
    my $ssh = shift;

    $ssh->_connect;
    $ssh->fatal_disconnect("Permission denied") unless $ssh->_login;

    if ($ssh->{config}->get('compression')) {
        eval { require Compress::Zlib; };
        if ($@) {
            $ssh->debug("Compression is disabled because Compress::Zlib can't be loaded.");
        }
        else {
            my $level = $ssh->{config}->get('compression_level') || 6;
            $ssh->debug("Requesting compression at level $level.");
            my $packet = $ssh->packet_start(SSH_CMSG_REQUEST_COMPRESSION);
            $packet->put_int32($level);
            $packet->send;

            $packet = Net::SSH::Perl::Packet->read($ssh);
            if ($packet->type == SSH_SMSG_SUCCESS) {
                $ssh->compression($level);
            }
            else {
                $ssh->debug("Warning: Remote host refused compression.");
            }
        }
    }

    if ($ssh->{config}->get('use_pty')) {
        $ssh->debug("Requesting pty.");
        my($packet);
        $packet = $ssh->packet_start(SSH_CMSG_REQUEST_PTY);
        my($term) = $ENV{TERM} =~ /(\w+)/;
        $packet->put_str($term);
        $packet->put_int32(0) for 1..4;
        $packet->put_int8(0);
        $packet->send;

        $packet = Net::SSH::Perl::Packet->read($ssh);
        unless ($packet->type == SSH_SMSG_SUCCESS) {
            $ssh->debug("Warning: couldn't allocate a pseudo tty.");
        }
    }
}

sub cmd {
    my $ssh = shift;
    my $cmd = shift;
    my $stdin = shift;

    $ssh->_setup_connection;

    my($packet);

    $ssh->debug("Sending command: $cmd");
    $packet = $ssh->packet_start(SSH_CMSG_EXEC_CMD);
    $packet->put_str($cmd);
    $packet->send;

    if (defined $stdin) {
        $packet = $ssh->packet_start(SSH_CMSG_STDIN_DATA);
        $packet->put_str($stdin);
        $packet->send;

        $packet = $ssh->packet_start(SSH_CMSG_EOF);
        $packet->send;
    }

    $ssh->register_handler(SSH_SMSG_STDOUT_DATA,
        sub { $ssh->{_cmd_stdout} .= $_[1]->get_str });
    $ssh->register_handler(SSH_SMSG_STDERR_DATA,
        sub { $ssh->{_cmd_stderr} .= $_[1]->get_str });
    $ssh->register_handler(SSH_SMSG_EXITSTATUS,
        sub { $ssh->{_cmd_exit} = $_[1]->get_int32 });

    $ssh->_start_interactive(1);
    my($stdout, $stderr, $exit) =
        map $ssh->{"_cmd_$_"}, qw( stdout stderr exit );

    $ssh->_disconnect;
    ($stdout, $stderr, $exit);
}

sub shell {
    my $ssh = shift;

    $ssh->{config}->set('use_pty', 1)
        unless defined $ssh->{config}->get('use_pty');
    $ssh->_setup_connection;

    $ssh->debug("Requesting shell.");
    my $packet = $ssh->packet_start(SSH_CMSG_EXEC_SHELL);
    $packet->send;

    $ssh->register_handler(SSH_SMSG_STDOUT_DATA,
        sub { syswrite STDOUT, $_[1]->get_str });
    $ssh->register_handler(SSH_SMSG_STDERR_DATA,
        sub { syswrite STDERR, $_[1]->get_str });
    $ssh->register_handler(SSH_SMSG_EXITSTATUS, sub {});

    $ssh->_start_interactive(0);

    $ssh->_disconnect;
}

sub _start_interactive {
    my $ssh = shift;
    my($sent_stdin) = @_;

    $ssh->debug("Entering interactive session.");

    my $h = $ssh->{client_handlers};

    my $s = IO::Select->new;
    $s->add($ssh->{session}{sock});
    $s->add(\*STDIN) unless $sent_stdin;

    CLOOP:
    while (1) {
        my @ready = $s->can_read;
        for my $a (@ready) {
            if ($a == $ssh->{session}{sock}) {
                my $buf;
                sysread $a, $buf, 8192;
                ($buf) = $buf =~ /(.*)/s;  ## Untaint data. Anything allowed.
                $ssh->incoming_data->append($buf);
            }
            elsif ($a == \*STDIN) {
                my $buf;
                sysread STDIN, $buf, 8192;
                ($buf) = $buf =~ /(.*)/s;  ## Untaint data. Anything allowed.
                my $packet = $ssh->packet_start(SSH_CMSG_STDIN_DATA);
                $packet->put_str($buf);
                $packet->send;
            }
        }

        while (my $packet = Net::SSH::Perl::Packet->read_poll($ssh)) {
            if (my $code = $h->{ $packet->type }) {
                $code->($ssh, $packet);
            }
            else {
                $ssh->debug(sprintf
                    "Warning: ignoring packet of type %d", $packet->type);
            }

            last CLOOP if $packet->type == SSH_SMSG_EXITSTATUS;
        }
    }

    my $packet = $ssh->packet_start(SSH_CMSG_EXIT_CONFIRMATION);
    $packet->send;
}

sub incoming_data {
    my $ssh = shift;
    if (!exists $ssh->{session}{incoming_data}) {
        $ssh->{session}{incoming_data} = Net::SSH::Perl::Buffer->new;
    }
    $ssh->{session}{incoming_data};
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

I<Net::SSH::Perl> is an all-Perl module implementing an SSH client.
It implements the SSH1 protocol; SSH2 functionality will come at
some point in the future.

I<Net::SSH::Perl> enables you to simply and securely execute commands
on remote machines, and receive the STDOUT, STDERR, and exit status
of that remote command. It contains built-in support for various
methods of authenticating with the server (password authentication,
RSA challenge-response authentication, etc.). It completely implements
the I/O buffering, packet transport, and user authentication layers
of the SSH protocol, and makes use of external Perl libraries (in
the Crypt:: family of modules) to handle encryption of all data sent
across the insecure network. It can also read your existing SSH
configuration files (F</etc/ssh_config>, etc.), RSA identity files,
known hosts files, etc.

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

=item * compression

If set to a true value, compression is turned on for the session
(assuming that the server supports it).

Compression is off by default.

Note that compression requires that you have the I<Compress::Zlib>
module installed on your system. If the module can't be loaded
successfully, compression is disabled; you'll receive a warning
stating as much if you having debugging on (I<debug> set to 1),
and you try to turn on compression.

=item * compression_level

Specifies the compression level to use if compression is enabled
(note that you must provide both the I<compression> and
I<compression_level> arguments to set the level; providing only
this argument will not turn on encryption).

The default value is 6.

=item * use_pty

Set this to 1 if you want to request a pseudo tty on the remote
machine. This is really only useful if you're setting up a shell
connection (see the I<shell> method, below); and in that case,
unless you've explicitly declined a pty (by setting I<use_pty>
to 0), this will be set automatically to 1. In other words,
you probably won't need to use this, often.

The default is 1 if you're starting up a shell, and 0 otherwise.

=item * options

Used to specify additional options to the configuration settings;
useful for specifying options for which there is no separate
constructor argument. This is analogous to the B<-o> command line
flag to the I<ssh> program.

If used, the value should be a reference to a list of option
directives in the format used in the config file. For example:

    my $ssh = Net::SSH::Perl->new("host", options => [
        "BatchMode yes", "RhostsAuthentication no" ]);

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

NOTE: the ssh protocol does not easily support (so far as I
know) running multiple commands per connection, unless those
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

=head2 $ssh->shell

Opens up an interactive shell on the remote machine and connects
it to your STDIN. This is most effective when used with a
pseudo tty; otherwise you won't get a command line prompt,
and it won't look much like a shell. For this reason--unless
you've specifically declined one--a pty will be requested
from the remote machine, even if you haven't set the I<use_pty>
argument to I<new> (described above).

This is really only useful in an interactive program.

In addition, you'll probably want to set your terminal to raw
input before calling this method. This lets I<Net::SSH::Perl>
process each character and send it off to the remote machine,
as you type it.

To do so, use I<Term::ReadKey> in your program:

    use Term::ReadKey;
    ReadMode('raw');
    $ssh->shell;
    ReadMode('restore');

In fact, you may want to place the C<restore> line in an I<END>
block, in case your program exits prior to reaching that line.

If you need an example, take a look at F<eg/pssh>, which
uses almost this exact code to implement an ssh shell.

=head2 $ssh->register_handler($packet_type, $subref)

Registers an anonymous subroutine handler I<$subref> to handle
packets of type I<$packet_type> during the client loop. The
client loop is entered after the client has sent a command
to the remote server, and after any STDIN data has been sent;
it consists of reading packets from the server (STDOUT
packets, STDERR packets, etc.) until the server sends the exit
status of the command executed remotely. At this point the client
exits the client loop and disconnects from the server.

When you call the I<cmd> method, the client loop by default
simply sticks STDOUT packets into a scalar variable and returns
that value to the caller. It does the same for STDERR packets,
and for the process exit status. (See the docs for I<cmd>).

You can, however, override that default behavior, and instead
process the packets yourself as they come in. You do this by
calling the I<register_handler> method and giving it a
packet type I<$packet_type> and a subroutine reference
I<$subref>. Your subroutine will receive as arguments the
I<Net::SSH::Perl> object (with an open connection to the sshd),
and a I<Net::SSH::Perl::Packet> object, which represents the
packet read from the server.

I<$packet_type> should be an integer constant; you can import
the list of constants into your namespace by explicitly loading
the I<Net::SSH::Perl::Constants> module:

    use Net::SSH::Perl::Constants qw( :msg );

This will load all of the I<MSG> constants into your namespace
so that you can use them when registering the handler. To do
that, use this method. For example:

    $ssh->register_handler(SSH_SMSG_STDOUT_DATA, sub {
        my($ssh, $packet) = @_;
        print "I received this: ", $packet->get_str;
    });

To learn about the methods that you can call on the packet object,
take a look at the I<Net::SSH::Perl::Packet> docs, as well as the
I<Net::SSH::Perl::Buffer> docs (the I<get_*> and I<put_*> methods).

Obviously, writing these handlers requires some knowledge of the
contents of each packet. For that, read through the SSH RFC, which
explains each packet type in detail. There's a I<get_*> method for
each datatype that you may need to read from a packet.

Take a look at F<eg/remoteinteract.pl> for an example of interacting
with a remote command through the use of I<register_handler>.

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

=head2 $ssh->incoming_data

Incoming data buffer, an object of type I<Net::SSH::Perl::Buffer>.
Returns the buffer object.

The idea behind this is that we our socket is non-blocking, so we
buffer input and periodically check back to see if we've read a
full packet. If we have a full packet, we rip it out of the incoming
data buffer and process it, returning it to the caller who
presumably asked for it.

This data "belongs" to the underlying packet layer in
I<Net::SSH::Perl::Packet>. Unless you really know what you're
doing you probably don't want to disturb that data.

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

=head2 $ssh->compression([ $level ])

Without arguments, returns the current compression level for the
session. If given an argument I<$level>, sets the compression level
and turns on compression for the session.

Note that this should I<not> be used to turn compression off. In fact,
I don't think there's a way to turn compression off. But in other
words, don't try giving this method a value of 0 and expect that to
turn off compression. It won't.

If the return value of this method is undefined or 0, compression
is turned off.

=head2 $ssh->send_compression

Returns the "send" compression object/stream. This is a
I<Compress::Zlib> deflation (compression) stream; we keep it around
because it contains state that needs to be used throughout the
session.

=head2 $ssh->receive_compression

Returns the "receive" compression object/stream. This is a
I<Compress::Zlib> inflation (uncompression) stream; we keep it
around because it contains state that needs to be used throughout
the session.

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
