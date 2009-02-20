#!/usr/bin/perl -w
use strict;
use ExtUtils::MakeMaker;
use File::Spec ();
use Config     ();

# is libnet-config available?
die "libnet 1.1 or later is required\n", "unable to find libnet-config in PATH\n"
  unless grep { -x File::Spec->catfile( $_, 'libnet-config' . $Config::Config{_exe} ) }
	  File::Spec->path;

# die if MakeMaker can't find the libs
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
	LICENSE       => 'perl',
	VERSION_FROM  => 'Arping.pm',
	ABSTRACT_FROM => 'Arping.pm',
	PREREQ_PM     => { 'Test::More' => 0, },
	AUTHOR        => 'Oleg Prokopyev <riiki@gu.net>, Radoslaw Zielinski <radek@pld-linux.org>',
	LIBS          => ['-lnet -lpcap'],
	DEFINE        => `libnet-config --defines`,
	INC           => `libnet-config --cflags`,
);

# vim: ts=4 sw=4 noet tw=100
