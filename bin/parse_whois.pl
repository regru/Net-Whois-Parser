#!/usr/bin/perl

#use FindBin '$Bin';
#use lib "$Bin/../lib";

use Net::Whois::Parser;
use YAML::Tiny;
print YAML::Tiny::Dump( parse_whois( domain => $ARGV[0] ) );
