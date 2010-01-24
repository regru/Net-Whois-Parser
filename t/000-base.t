#!/usr/bin/perl

use strict;

use Test::More;

use lib qw( lib ../lib );

use Net::Whois::Raw;
use Net::Whois::Parser;
$Net::Whois::Parser::DEBUG = 2;

my $domain = 'reg.ru';
my $raw = '';
my $info;

plan tests => 10;

my ( $raw, $server ) = whois($domain);


ok parse_whois(raw => $raw, server => $server), "parse_whois $domain, $server";
ok parse_whois(raw => $raw, domain => $domain), "parse_whois $domain, $server";
ok parse_whois(domain => $domain), "parse_whois $domain, $server";

ok !parse_whois(domain => 'iweufhweufhweufh.ru'), 'domain not exists';

$info = parse_whois(raw => $raw, server => $server);
is $info->{nameservers}->[0]->{domain}, 'ns1.reg.ru', 'reg.ru ns 1';
is $info->{nameservers}->[1]->{domain}, 'ns2.reg.ru', 'reg.ru ns 2';
is $info->{emails}->[0], 'info@reg.ru', 'reg.ru email';

$raw = "
    Test   1: test
 Test-2:wefwef wef
  test3: value:value
";
$info = parse_whois( raw => $raw );

ok exists $info->{'test_1'}, 'field name with spaces';
ok exists $info->{'test_2'}, 'field with -';
is $info->{'test3'}, 'value:value', 'field value with :';

####
$Net::Whois::Parser::ONLY_LAST_VALUE = 1;

$raw = [
    { text => "test: error" },
    { text => "test: ok" },
];
$info = parse_whois( raw => $raw );

is $info->{test}, 'ok', 'only_last_value is on';


