#!/usr/bin/perl

use strict;

use Test::More qw(no_plan);

use lib qw( lib ../lib );

use Net::Whois::Parser;
use Data::Dumper;

my $domain = $ARGV[0] || 'reg.ru';


# Проверяем работоспособность парсера на всех зонах
for my $zone ( keys %Net::Whois::Raw::Data::servers ) {

    print "$zone\n";
    $zone = lc $zone;
    my $domain = "www.$zone";

    my $d_info = parse_whois(domain => $domain);
    ok $d_info, "\t\t$zone\tparse_whois";

    ok exists $d_info->{nameservers}, "\t\t$zone\tnameservers";
    ok exists $d_info->{emails}, "\t\t$zone\temails";

    #warn Dumper($domain_info->whois_fields);

}

