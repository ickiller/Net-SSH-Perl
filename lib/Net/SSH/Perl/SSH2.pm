# $Id: SSH2.pm,v 1.20 2001/04/24 23:23:43 btrott Exp $

package Net::SSH::Perl::SSH2;
use strict;

use Net::SSH::Perl::Kex;
use Net::SSH::Perl::ChannelMgr;
use Net::SSH::Perl::Packet;
use Net::SSH::Perl::Buffer qw( SSH2 );
use Net::SSH::Perl::Constants qw( :protocol :msg2 );
use Net::SSH::Perl::Cipher;
use Net::SSH::Perl::Auth;
use Net::SSH::Perl::Comp;
use Net::SSH::Perl::Util qw( :hosts );

use Net::SSH::Perl;
use base qw( Net::SSH::Perl );

use Carp qw( croak );

sub _dup {
    my($fh, $mode) = @_;
    my $dup = Symbol::gensym;
    my $str = "${mode}&$fh";
    open $dup, $str;
    $dup;
}

sub version_string {
    my $class = shift;
    sprintf "Net::SSH::Perl Version %s, protocol version %s.%s.",
        $class->VERSION, PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2;
}

sub _proto_init {
    my $ssh = shift;
    unless ($ssh->{config}->get('user_known_hosts')) {
        $ssh->{config}->set('user_known_hosts', "$ENV{HOME}/.ssh/known_hosts2");
    }
    unless ($ssh->{config}->get('global_known_hosts')) {
        $ssh->{config}->set('global_known_hosts', "/etc/ssh_known_hosts2");
    }
    unless (my $if = $ssh->{config}->get('identity_files')) {
        $ssh->{config}->set('identity_files', [ "$ENV{HOME}/.ssh/id_dsa" ]);
    }

    for my $a (qw( password dsa )) {
        $ssh->{config}->set("auth_$a", 1)
            unless defined $ssh->{config}->get("auth_$a");
    }
}

sub kex { $_[0]->{kex} }

sub register_handler {
    my($ssh, $type, $sub) = @_;
    $ssh->{client_handlers}{$type} = $sub;
}

sub login {
    my $ssh = shift;
    $ssh->SUPER::login(@_);
    $ssh->_login or $ssh->fatal_disconnect("Permission denied");

    $ssh->debug("Login completed, opening dummy shell channel.");
    my $cmgr = $ssh->channel_mgr;
    my $channel = $cmgr->new_channel(
        ctype => 'session', local_window => 0,
        local_maxpacket => 0, remote_name => 'client-session');
    $channel->open;

    my $packet = Net::SSH::Perl::Packet->read_expect($ssh,
        SSH2_MSG_CHANNEL_OPEN_CONFIRMATION);
    $cmgr->input_open_confirmation($packet);

    $ssh->debug("Got channel open confirmation, requesting shell.");
    $channel->request("shell", 0);
}

sub _login {
    my $ssh = shift;
    my $user = $ssh->{config}->get('user');

    my $kex = Net::SSH::Perl::Kex->new($ssh);
    $kex->exchange;

    $ssh->debug("Sending request for user-authentication service.");
    my $packet = $ssh->packet_start(SSH2_MSG_SERVICE_REQUEST);
    $packet->put_str("ssh-userauth");
    $packet->send;

    $packet = Net::SSH::Perl::Packet->read($ssh);
    croak "denied SSH2_MSG_SERVICE_ACCEPT: ", $packet->type
        unless $packet->type == SSH2_MSG_SERVICE_ACCEPT;
    $ssh->debug("Service accepted: " . $packet->get_str . ".");

    $ssh->debug("Trying empty user-authentication request.");
    $packet = $ssh->packet_start(SSH2_MSG_USERAUTH_REQUEST);
    $packet->put_str($user);
    $packet->put_str("ssh-connection");
    $packet->put_str("none");
    $packet->send;

    my $valid = 0;
    my %auth_map = (password => 'Password', publickey => 'DSA');
    my(%tried, %auth);
    while (!$valid) {
        $packet = Net::SSH::Perl::Packet->read($ssh);
        $valid = 1, last
            if $packet->type == SSH2_MSG_USERAUTH_SUCCESS;
        croak "userauth error: bad message during authentication"
            unless $packet->type == SSH2_MSG_USERAUTH_FAILURE;

        my $authlist = $packet->get_str;
        my $partial = $packet->get_int8;
        $ssh->debug("Authentication methods that can continue: $authlist.");

        my($auth, $found);
        for my $meth ( split /,/, $authlist ) {
            $found = 0;
            next if !exists $auth_map{$meth};
            $auth = $auth{$meth};
            if (!$auth) {
                $auth = $auth{$meth} =
                    Net::SSH::Perl::Auth->new($auth_map{$meth}, $ssh);
            }
            next unless $auth->enabled;
            $ssh->debug("Next method to try is $meth.");
            $found++;
            if ($auth->authenticate($tried{$meth}++)) {
                last;
            }
            else {
                $auth->enabled(0);
            }
        }
        last unless $found;
    }

    $valid;
}

sub _session_channel {
    my $ssh = shift;
    my $cmgr = $ssh->channel_mgr;

    my $channel = $cmgr->new_channel(
        ctype => 'session', local_window => 32*1024,
        local_maxpacket => 16*1024, remote_name => 'client-session',
        rfd => _dup('STDIN', '<'), wfd => _dup('STDOUT', '>'),
        efd => _dup('STDERR', '>'));

    $channel;
}

sub _make_input_channel_req {
    my($r_exit) = @_;
    return sub {
        my($channel, $packet) = @_;
        my $rtype = $packet->get_str;
        my $reply = $packet->get_int8;
        $channel->{ssh}->debug("input_channel_request: rtype $rtype reply $reply");
        if ($rtype eq "exit-status") {
            $$r_exit = $packet->get_int32;
        }
        if ($reply) {
            my $r_packet = $channel->{ssh}->packet_start(SSH2_MSG_CHANNEL_SUCCESS);
            $r_packet->put_int($channel->{remote_id});
            $r_packet->send;
        }
    };
}

sub cmd {
    my $ssh = shift;
    my($cmd, $stdin) = @_;
    my $cmgr = $ssh->channel_mgr;
    my $channel = $ssh->_session_channel;
    $channel->open;

    $channel->register_handler(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, sub {
        my($channel, $packet) = @_;
        $channel->{ssh}->debug("Sending command: $cmd");
        my $r_packet = $channel->request_start("exec", 0);
        $r_packet->put_str($cmd);
        $r_packet->send;
    });

    my($exit);
    $channel->register_handler(SSH2_MSG_CHANNEL_REQUEST,
        _make_input_channel_req(\$exit));

    my $h = $ssh->{client_handlers};
    my($stdout, $stderr);
    if ($h->{stdout}) {
        $channel->register_handler("_output_buffer", $h->{stdout});
    }
    else {
        $channel->register_handler("_output_buffer", sub {
            $stdout .= $_[1]->bytes;
        });
    }
    if ($h->{stderr}) {
        $channel->register_handler("_extended_buffer", $h->{stderr});
    }
    else {
        $channel->register_handler("_extended_buffer", sub {
            $stderr .= $_[1]->bytes;
        });
    }

    $ssh->client_loop;

    ($stdout, $stderr, $exit);
}

sub shell {
    my $ssh = shift;
    my $cmgr = $ssh->channel_mgr;
    my $channel = $ssh->_session_channel;
    $channel->open;

    $channel->register_handler(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, sub {
        my($channel, $packet) = @_;
        my $r_packet = $channel->request_start('pty-req', 0);
        my($term) = $ENV{TERM} =~ /(\w+)/;
        $r_packet->put_str($term);
        $r_packet->put_int32(0) for 1..4;
        $r_packet->put_str("");
        $r_packet->send;
        $channel->{ssh}->debug("Requesting shell.");
        $channel->request("shell", 0);
    });

    my($exit);
    $channel->register_handler(SSH2_MSG_CHANNEL_REQUEST,
        _make_input_channel_req(\$exit));

    $channel->register_handler("_output_buffer", sub {
        syswrite STDOUT, $_[1]->bytes;
    });
    $channel->register_handler("_extended_buffer", sub {
        syswrite STDERR, $_[1]->bytes;
    });

    $ssh->client_loop;
}

sub client_loop {
    my $ssh = shift;
    my $cmgr = $ssh->channel_mgr;

    my $h = $cmgr->handlers;

    $ssh->debug("Entering interactive session.");

    CLOOP:
    my $quit_pending = 0;
    while (!$quit_pending) {
        while (my $packet = Net::SSH::Perl::Packet->read_poll($ssh)) {
            if (my $code = $h->{ $packet->type }) {
                $code->($cmgr, $packet);
            }
            else {
                $ssh->debug("Warning: ignore packet type " . $packet->type);
            }
        }

        my $rb = IO::Select->new;
        my $wb = IO::Select->new;
        $rb->add($ssh->sock);
        $cmgr->prepare_channels($rb, $wb);

        #last unless $cmgr->any_open_channels;
        my $oc = grep { defined } @{ $cmgr->{channels} };
        last unless $oc > 1;

        my($rready, $wready) = IO::Select->select($rb, $wb);
        $cmgr->process_input_packets($rready, $wready);

        for my $a (@$rready) {
            if ($a == $ssh->{session}{sock}) {
                my $buf;
                my $len = sysread $a, $buf, 8192;
                $quit_pending = 1 if $len == 0;
                ($buf) = $buf =~ /(.*)/s;  ## Untaint data. Anything allowed.
                $ssh->incoming_data->append($buf);
            }
        }
    }
}

## client sends CHANNEL_OPEN
## client sets up dispatch handlers, enters loop
## client receives CHANNEL_OPEN_CONFIRMATION
## client sends CHANNEL_REQUEST, requesting either cmd or shell
## if cmd:
##     client receives CHANNEL_DATA
##     dispatcher handles incoming input packets (client_process_buffered_input_packets)
##     channel mgr shoves incoming data into 'output' buffer (channel_input_data)
##     after select, loop through channels and process buffers (channel_after_select)
##     channel_post_open_2 handles all three file descriptors (channel_post_open_2)
##     client reads data from 'output' buffer and writes to wfd (channel_handle_wfd)

sub channel_mgr {
    my $ssh = shift;
    unless (defined $ssh->{channel_mgr}) {
        $ssh->{channel_mgr} = Net::SSH::Perl::ChannelMgr->new($ssh);
    }
    $ssh->{channel_mgr};
}

1;
__END__

=head1 NAME

Net::SSH::Perl::SSH2 - SSH2 implementation

=head1 SYNOPSIS

    use Net::SSH::Perl;
    my $ssh = Net::SSH::Perl->new($host, protocol => 2);

=head1 DESCRIPTION

I<Net::SSH::Perl::SSH2> implements the SSH2 protocol. It is a
subclass of I<Net::SSH::Perl>, and implements the interface
described in the documentation for that module. In fact, your
usage of this module should be completely transparent; simply
specify the proper I<protocol> value (C<2>) when creating your
I<Net::SSH::Perl> object, and the SSH2 implementation will be
loaded automatically.

NOTE: Of course, this is still subject to protocol negotiation
with the server; if the server doesn't support SSH2, there's
not much the client can do, and you'll get a fatal error if
you use the above I<protocol> specification (C<2>).

=head2 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
