package Net::SSH::Perl::Handle::SSH1;
use strict;

use Net::SSH::Perl::Buffer qw( SSH1 );
use Net::SSH::Perl::Constants qw(
    SSH_SMSG_STDOUT_DATA
    SSH_CMSG_STDIN_DATA
    SSH_CMSG_EOF );

use Carp qw( croak );
use Tie::Handle;
use base qw( Tie::Handle );

sub TIEHANDLE {
    my $class = shift;
    my($mode, $ssh, $r_exit) = @_;
    my $read = $mode =~ /^[rR]/;
    my $handle = bless { ssh => $ssh, exit => $r_exit }, $class;
    if ($read) {
        my $incoming = $handle->{incoming} = Net::SSH::Perl::Buffer->new;
        $ssh->register_handler(SSH_SMSG_STDOUT_DATA, sub {
            my($ssh, $packet) = @_;
            $incoming->append($packet->get_str);
            $ssh->break_client_loop;
        });
    }
    $handle;
}

sub READ {
    my $h = shift;
    my $buf = $h->{incoming};
    while (!$buf->length) {
        $h->{ssh}->_start_interactive;
        croak "Connection closed" unless $buf->length;
    }
    $_[0] = $buf->bytes;
    $buf->empty;
    length($_[0]);
}

sub WRITE {
    my $h = shift;
    my($data) = @_;
    my $packet = $h->{ssh}->packet_start(SSH_CMSG_STDIN_DATA);
    $packet->put_str($data);
    $packet->send;
    length($data);
}

sub EOF { defined ${$_[0]->{exit}} ? 1 : 0 }

sub CLOSE {
    my $h = shift;
    unless ($h->{incoming}) {
        my $ssh = $h->{ssh};
        my $packet = $ssh->packet_start(SSH_CMSG_EOF);
        $packet->send;
        $ssh->_start_interactive;
    }
}

1;
