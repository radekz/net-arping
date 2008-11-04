#!/usr/bin/perl -w
use strict;
use ExtUtils::MakeMaker;

local $SIG{__WARN__} = sub {
	if ( @_ && $_[0] =~ /probably harmless.+No library found/i ) {
		die @_, "ERROR: Net::Arping requires libnet 1.1 (or later) and libpcap";
	}
	else {
		warn @_;
	}
};

WriteMakefile(
	NAME          => 'Net::Arping',
	VERSION_FROM  => 'Arping.pm',
	ABSTRACT_FROM => 'Arping.pm',
	PREREQ_PM     => { 'Test::More' => 0, },
	AUTHOR        => 'Oleg Prokopyev <riiki@gu.net>, Radoslaw Zielinski <radek@pld-linux.org>',
	LIBS          => ['-lnet -lpcap'],
	DEFINE        => `libnet-config --defines`,
	INC           => `libnet-config --cflags`,
);
