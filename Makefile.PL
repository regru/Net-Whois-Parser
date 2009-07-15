use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => "Net::Whois::Parser",
	VERSION_FROM => "lib/Net/Whois/Parser.pm",
	'dist' => { COMPRESS=>"gzip", SUFFIX=>"gz" },
	AUTHOR => 'Ivan Sokolov <ivsokolov@cpan.org>',
	PREREQ_PM => {
		'Net::Whois::Raw' => 0,
	}
);
