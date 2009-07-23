use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => "Net::Whois::Parser",
	VERSION_FROM => "lib/Net/Whois/Parser.pm",
	'dist' => { COMPRESS=>"gzip", SUFFIX=>"gz" },
	AUTHOR => 'Ivan Sokolov <ivsokolov@cpan.org>',
        LICENSE => 'perl',
	PREREQ_PM => {
                'Test::More' => 0,
		'Net::Whois::Raw' => 0,
	}
);
