#!/usr/bin/perl -w
use strict;
use Test::More tests => 3;

use Net::Arping ();

ok( my $aping = Net::Arping->new );

SKIP: {
	skip 'UID==0 (root) required', 2 unless $> == 0;

	my %ip;
	my $arp = find_in_path('arp');
	my $ip  = find_in_path('ip');
	$ip{$_}++ for grep $_, map /^((?:\d+\.){3}\d+)\s/,    # find IP addresses to "arping"
	  ( $ip  ? `\Q$ip\E neigh` : () ),                    # /sbin/ip neigh
	  ( $arp ? `\Q$arp\E -n`   : () );                    # /sbin/arp -n

	SKIP: {
		unless (%ip) {
			warn 'tests not reliable; no IP addresses found';
			skip 'failed to find an IP address to ARP', 1;
		}
		my $ok = grep /^(?:[a-f\d]{2}:)+/i, map $aping->arping($_), keys %ip;
		ok( $ok, 'ARP-ping at least one IP address' );
	}

	ok( !$aping->arping(Host => '192.0.2.1'), 'arping for non-existant address' );    # RFC 3330
}

sub find_in_path {
	require File::Spec;
	require Config;
	my $program = shift;
	return +(
		grep -x,
		map File::Spec->catfile( $_, $program . $Config::Config{_exe} ),
		qw( /sbin /usr/sbin /usr/local/sbin ),
		split /:/, $ENV{PATH}
	)[0];
}
