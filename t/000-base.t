#!/usr/bin/perl

use strict;

use Test::More qw(no_plan);

use lib qw( lib ../lib );

use Net::Whois::Raw;
use Net::Whois::Parser;
$Net::Whois::Parser::DEBUG = 2;

use Data::Dumper;

my $domain = $ARGV[0] || 'reg.ru';

my ( $raw, $server ) = whois($domain);


ok parse_whois(raw => $raw, server => $server), "parse_whois $domain, $server";
ok parse_whois(raw => $raw, domain => $domain), "parse_whois $domain, $server";
ok parse_whois(domain => $domain), "parse_whois $domain, $server";

if ( $domain eq 'reg.ru' ) {
    my $info = parse_whois(raw => $raw, server => $server);

    is $info->{nameservers}->[0]->{domain}, 'ns1.reg.ru', 'reg.ru ns 1';
    is $info->{nameservers}->[1]->{domain}, 'ns2.reg.ru', 'reg.ru ns 2';
    is $info->{emails}->[0], 'info@reg.ru', 'reg.ru email';
}




