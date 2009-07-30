use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Net::Whois::Parser',
    license             => 'perl',
    dist_author         => 'Ivan Sokolov <ivsokolov@cpan.org>',
    dist_version_from   => 'lib/Net/Whois/Parser.pm',
    build_requires => {
        'Test::More' => 0,
	'Net::Whois::Raw' => 2.0,
    },
    add_to_cleanup      => [ 'Net-Whois-Parser-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
