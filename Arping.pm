package Net::Arping;

use strict;
use Carp;

require Exporter;
our @ISA = qw(Exporter);

our $VERSION    = '0.03_02';
our $XS_VERSION = $VERSION;
$VERSION = eval $VERSION;

our @EXPORT_OK = qw(&send_arp);

require XSLoader;
XSLoader::load( 'Net::Arping', $XS_VERSION );

use vars qw( $default_timeout );    # backward-compatibility only
$default_timeout = 1;               # default timeout is 1 second

sub usage {
	croak << 'EOF';
Usage:
	$q->arpping($host)
 or
	$q->arping(Host => $host [, Interface => $interface, Timeout => $sec ])
EOF
}

sub new {
	my $class = shift;
	return bless {}, $class;
}

sub arping {
	my $self = shift;
	my ( $host, $result );

	usage() if !@_;

	if ( @_ == 1 ) {
		$host = shift;
		return send_arp( $host, $default_timeout );
	}
	else {
		my %args = @_;

		usage()
		  unless $args{Host} && $args{Host} =~ m/^[A-Za-z0-9-.]+$/
			  and !exists $args{Timeout} || $args{Timeout} =~ /^\d+$/ && $args{Timeout} > 0
			  and !exists $args{Interface} || $args{Interface} =~ /^\S+$/;

		return send_arp(
			$args{Host},
			( exists $args{Timeout}   ? $args{Timeout}   : $default_timeout ),
			( exists $args{Interface} ? $args{Interface} : () ),
		);
	}
}
1;
__END__

=head1 NAME

Net::Arping - Ping remote host by ARP packets 

=head1 SYNOPSIS

  use Net::Arping ();

  my $q = Net::Arping->new();

  if ( my $result = $q->arping($host) ) {
        print "'$host' is alive, the MAC address is $result\n";
  }
  else {
        print "'$host' is not responding.\n";
  }

You can also specify the source interface and timeout. Default timeout
is 1 second.

  my $result = $q->arping( Host => $host, Interface => 'eth0', Timeout => 4 );
  if ( $result ) {
        print "'$host' is alive, the MAC address is $result\n";
  }
  else {
        print "'$host' is not responding on eth0.\n";
  }

=head1 DESCRIPTION

The module contains function for testing remote host reachability
by sending ARP packets.

The program must be run as root or be setuid to root.

This module uses the libnet and pcap libraries, available here:
L<http://www.packetfactory.net/libnet/>
L<http://www.tcpdump.org/#latest>.

=head1 FUNCTIONS

=over 2

=item Net::Arping->new();

Create a new arping object.

=item $q->arping($host)

=item $q->arping(Host => $host [, Interface => $interface, Timeout => $sec ])

Arping the remote host. Interface and Timeout parameters are optional.
Default timeout is 1 second. Default device is selected
by libnet_select_device function.

=item Net::Arping::send_arp( $host, $interface, $timeout )

An exportable function (NOTE: not a method).

=back

=head1 BUGS

Libnet (up to and including v1.1.2.1) leaks file descriptors, if the C<Interface>
argument is not provided.  A patch is available; see below.

=head1 COPYRIGHT
                                                                                
Copyright (c) 2002 Oleg Prokopyev. All rights reserved. It's a free software. 
You can redistribute it and/or modify it under the same terms as Perl 
itself.

=head1 SEE ALSO

pcap(3), libnet(3), L<http://cvs.pld-linux.org/SOURCES/libnet-leaking-fd.patch>

=head1 AUTHOR

Oleg Prokopyev, E<lt>riiki@gu.netE<gt>

Maintained by Radoslaw Zielinski E<lt>radek@pld-linux.orgE<gt>, L<http://radek.cc/>.

=cut

# vim: ts=4 sw=4 noet tw=100
