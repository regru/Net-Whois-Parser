#!/usr/bin/perl

use strict;
use utf8;

use FindBin '$Bin';
use lib "$Bin/../lib";
use Data::Dumper;

use Net::Whois::Parser;
$Net::Whois::Raw::CHECK_FAIL = 1;
$Net::Whois::Raw::TIMEOUT = 10;

my $info = parse_whois( domain => $ARGV[0] || 'reg.ru' );

print $info ? Dumper($info) : "failed\n";


