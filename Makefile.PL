#!/usr/bin/perl -w
use strict;
use ExtUtils::MakeMaker;

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
