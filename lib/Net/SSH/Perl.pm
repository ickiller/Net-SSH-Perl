package Net::SSH::Perl;
use strict;

use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Constants qw/:msg :hosts PROTOCOL_MAJOR PROTOCOL_MINOR/;
use Net::SSH::Perl::Cipher;
use Net::SSH::Perl::Auth;
use Net::SSH::Perl::Util qw/:hosts _compute_session_id _rsa_public_encrypt/;
use Carp qw/croak/;

use vars qw/$VERSION/;
use Socket;
use Symbol;
use Math::GMP;

$VERSION = "0.51";

sub new {
    my $class = shift;
    my $host = shift;
    croak "usage: ", __PACKAGE__, "->new(\$host)"
        unless defined $host;
    my $ssh = bless { host => $host, @_ }, $class;
    if ($ssh->{cipher}) {
        my $cid;
        unless ($cid = Net::SSH::Perl::Cipher::id($ssh->{cipher})) {
            croak "Cipher '$ssh->{cipher}' is unknown.";
        }
        unless (Net::SSH::Perl::Cipher::supported($cid)) {
            croak "Cipher '$ssh->{cipher}' is not supported.";
        }
    }
    if (scalar getpwuid($<) eq "root" && !exists $ssh->{privileged}) {
        $ssh->{privileged} = 1;
    }
    $ssh->debug(sprintf "Net::SSH Version $VERSION, protocol version %s.%s.",
        PROTOCOL_MAJOR, PROTOCOL_MINOR);
    $ssh;
}

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
    croak "Net::SSH: Couldn't resolve $ssh->{host} to numerical address"
        unless defined $raddr;
    my $rport = $ssh->{port} || 'ssh';
    if ($rport =~ /\D/) {
        my @serv = getservbyname($rport, 'tcp');
        $rport = $serv[2];
    }
    $ssh->debug("Connecting to $ssh->{host}, port $rport.");
    connect($sock, sockaddr_in($rport, $raddr));

    select((select($sock), $|=1)[0]);

    $ssh->{session}{sock} = $sock;
    $ssh->_exchange_identification;

    $ssh->debug("Connection established.");
}

sub _create_socket {
    my $ssh = shift;
    my $sock = gensym;
    if ($ssh->{privileged}) {
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
        $ssh->{localport} = $p;
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
    $packet->send;
    $ssh->{session} = {};
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
    print STDERR "@_\n" if $ssh->{debug};
}

sub login {
    my $ssh = shift;
    ($ssh->{user}, $ssh->{pass}) = @_;
    $ssh->{pass} = $CONFIG->{ssh_password} if exists $CONFIG->{ssh_password};
    $ssh->{user} = scalar getpwuid($<) unless defined $ssh->{user};
}

sub _login {
    my $ssh = shift;
    my $user = $ssh->{user};
    croak "No user defined" unless $user;

    $ssh->debug("Waiting for server public key.");
    my $packet = Net::SSH::Perl::Packet->read_expect($ssh, SSH_SMSG_PUBLIC_KEY);

    my $data = $packet->data;
    my $check_bytes = $data->bytes(0, 8, "");

    my %keys;
    for my $which (qw/public host/) {
        $keys{$which}{bits} = $data->get_32bit;
        $keys{$which}{e}    = $data->get_mp_int;
        $keys{$which}{n}    = $data->get_mp_int;
    }

    my $protocol_flags = $data->get_32bit;
    my $supported_ciphers = $data->get_32bit;
    my $supported_auth = $data->get_32bit;

    $ssh->debug(sprintf "Received server public key (%d bits) and " .
        "host key (%d bits).", $keys{public}{bits}, $keys{host}{bits});

    my $session_id =
      _compute_session_id($check_bytes, $keys{host}, $keys{public});
    $ssh->{session}{id} = $session_id;

    my $status =
      _check_host_in_hostfile($ssh->{host},
      "$ENV{HOME}/.ssh/known_hosts", $keys{host});

    unless (defined $status && $status == HOST_OK) {
        $status =
          _check_host_in_hostfile($ssh->{host},
          "/etc/ssh_known_hosts", $keys{host});
    }

    if ($status == HOST_OK) {
        $ssh->debug(sprintf "Host '%s' is known and matches the host key.",
            $ssh->{host});
    }
    elsif ($status == HOST_NEW) {
        $ssh->debug(sprintf "Host key for host '%s' not found from the list " .
            "of known hosts... adding.", $ssh->{hosts});
        _add_host_to_hostfile($ssh->{host},
            "$ENV{HOME}/.ssh/known_hosts", $keys{host});
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
    if ($cipher_name = $ssh->{cipher}) {
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
    $packet->put_char(pack "c", $cipher);
    $packet->put_char($_) for split //, $check_bytes;
    $packet->put_mp_int($skey);
    $packet->put_32bit(0);    ## No protocol flags.
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
        croak sprintf "Protocol error: got %d in response to SSH_CMSG_USER",
            $packet->type;
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
    croak "Permission denied" unless $ssh->_login;

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
    $h->{+SSH_SMSG_EXITSTATUS}  ||= sub { $exit    = $_[1]->get_32bit };

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
            croak sprintf "Didn't expect packet of type %d; buffer is %s\n",
                $pack->type, $pack->bytes;
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

=head1 INSTALLATION

I<Net::SSH::Perl> installation is relatively straightforward. The
only slightly complicated bit is that you'll need to install
Crypt:: modules depending on which ciphers you wish to use.
This has been made quite easy if you use the CPAN shell to
install Net::SSH::Perl; the installation process will ask you which
ciphers you wish to have installed, and will then add the
Crypt:: modules as prerequisites. The CPAN shell should then
install them automatically.

Even if you're not using the CPAN shell, the installation script
tries to make things easy by detecting which modules you'll need
to install, then loading the CPAN shell and installing them,
if you want.

If you don't like either of those options you'll need to do the
installations manually. In which case you'll need to install
Math::GMP (version 1.04 or greater), String::CRC32 (version 1.2
or greater), and Digest::MD5, plus any additional Crypt:: modules
you wish to use. 

Net::SSH::Perl itself installs like a Perl module should:

    % perl Makefile.PL
    % make && make test && make install

=head1 DESCRIPTION

I<Net::SSH::Perl> is an all-Perl module implementing an ssh client.
In other words, it isn't a wrapper around the actual ssh
client, which is both good and bad. The good is that you don't
have to fork another process to connect to an sshd daemon,
so you save on overhead, which is a big win. The bad is that
currently I<Net::SSH::Perl> doesn't support all of the authentication
protocols and encryption ciphers that the actual I<ssh> program does,
so you can't take advantage of them. (For a list of what ciphers
and auth methods are supported, keep reading.)

Of course, I think that the good outweighs the bad (particularly
since the bad is something that can be improved and worked on),
and that's why I<Net::SSH::Perl> exists.

=head1 USAGE

Usage of I<Net::SSH::Perl> is very simple.

=head2 Net::SSH::Perl->new($host, %params)

To set up a new connection, call the I<new> method, which
connects to I<$host> and returns a I<Net::SSH::Perl> object.

I<new> accepts the following named parameters in I<%params>:

=over 4

=item * cipher

Specifies the name of the encryption cipher that you wish to
use for this connection. This must be one of the supported
ciphers (currently, I<IDEA>, I<DES>, and I<DES3>); specifying
an unsupported cipher is a fatal error. The default cipher
is I<IDEA>.

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

=back

=head2 $ssh->login([ $user [, $password ] ])

Sets the username and password to be used when authenticating
with the I<sshd> daemon. The username I<$user> is required for
all authentication protocols (to identify yourself to the
remote server), but if you don't supply it the currently
logged-in user is used instead.

The password I<$password> is needed only for password
authentication (it's not used for RSA passphrase authentication,
though perhaps it should be). And if you're running in an
interactive session and you've not provided a password, you'll
be prompted for one.

=head2 $ssh->cmd($cmd, [ $stdin ])

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

=head1 ENCRYPTION CIPHERS

I<Net::SSH::Perl> currently supports 4 encryption ciphers: IDEA,
DES, 3DES, and Blowfish.

In order to use the ciphers you'll need to install the
corresponding Crypt:: module. I've not listed any of these
modules as prerequisites above, but during the installation
process you'll be prompted to add some of these modules
so that you can use the encryption. If you're using the CPAN
shell, the modules should be automatically installed;
otherwise you'll need to do so yourself.

=head1 AUTHOR

Benjamin Trott, ben@rhumba.pair.com

=head1 SUPPORT

Take a look at the scripts in F<eg/> for help and examples of
using Net::SSH::Perl. F<eg/cmd.pl> is just a simple example of
some of the functionality, F<eg/pssh> is an ssh-like client
for running commands on other servers, and F<eg/pscp> is a very
simple scp-like script. Both pssh and pscp support a subset
of the command line options that the actual tools support;
obviously, only those options supported by Net::SSH::Perl are
supported by pssh and pscp.

If you have any questions, code samples, bug reports, or
feedback, please email them to:

    ben@rhumba.pair.com

=head1 COPYRIGHT

(C) 2001 Benjamin Trott. All rights reserved.

=cut
