package Net::Whois::Parser;

use strict;
use warnings;
use Data::Dumper;

use Net::Whois::Raw;

our $VERSION = '0.01';

our @EXPORT = qw( parse_whois );

our $DEBUG = 0; 

our %PARSERS = ( 
    'DEFAULT' => \&_default_parser,
);

our %FIELD_NAME_CONV = (
    'e-mail'      => 'emails',
    'nserver'     => 'nameservers',        
    'Name Server' => 'nameservers',        
    'Domain name' => 'domain',
);

# From Net::Whois::Raw
sub import {
    my $mypkg = shift;
    my $callpkg = caller;

    no strict 'refs';

    # export subs
    *{"$callpkg\::$_"} = \&{"$mypkg\::$_"} foreach ((@EXPORT, @_));
}

# fetches whois text
sub _fetch_whois {
    my %args = @_;
	
    my @res = eval { 
        Net::Whois::Raw::whois( 
            $args{domain}, 
            $args{server} || undef, 
            $args{which_whois} || 'QRY_ALL'
        )
    };

    my $res = ref $res[0] ? $res[0] : [ { text => $res[0], srv => $res[1] } ];
    @$res = grep { $_->{text} } @$res;

    return scalar @$res ? $res : undef;
}

sub parse_whois {
    my %args = @_;

    if ( $args{raw} ) {

        my $server = 
            $args{server} || 
            Net::Whois::Raw::Common::get_server($args{domain}) ||
            'DEFAULT';
        
        my $whois = ref $args{raw} ? $args{raw} : [ { text => $args{raw}, srv => $server } ];
        

        return _process_parse($whois);

    }
    elsif ( $args{domain} ) {
        
        return _process_parse( _fetch_whois(%args) );

    }
    
    undef;
}

sub _process_parse {
    my ( $whois ) = @_;

    my %data = ();
    for my $ans ( @$whois ) {

        my $parser = $PARSERS{$ans->{srv}} || $PARSERS{DEFAULT};

        %data = (
            %data,
            %{ _post_parse( $parser->($ans->{text}) ) }
        );
    }
    \%data;
}

# стандартизация полученных от парсера данных
sub _post_parse {
    my ( $data )  = @_;
    
    for my $key ( keys %$data ) {

        my $value = $data->{$key};
        
        delete $data->{$key}, next unless $value;
        
        # Изменение ключа
        if ( exists $FIELD_NAME_CONV{$key} ) {
            delete $data->{$key};

            $key =  $FIELD_NAME_CONV{$key};
        
            $value = [ @$value, @{$data->{$key}} ] 
                if $data->{$key};

        }
        
        @$value = _make_unique(@$value) if $#$value > 0;

        # форматирование полей и запись в хеш
        if ( $key eq 'nameservers' ) {
            my @nss;
            for my $ns ( @$value ) {
                my ( $domain, $ip ) = split /\s+/, $ns;

                $domain ||= $ns;
                $domain =~ s/\.$//;
                $domain = lc $domain;

                push @nss, { 
                    domain => $domain, 
                    ( $ip ? (ip => $ip) : () )
                }; 
            }
            $data->{$key} = \@nss;
        }
        elsif ( $key eq 'emails' ) {
            $data->{$key} = $value;
        }
        else {
            $data->{$key} = scalar @$value > 1 ? $value : $value->[0];
            
        } 
        
    }
    $data;
}

sub _make_unique {
    my %vals;
    grep { not $vals{$_} ++ } @_;
}

## PARSERS ##

# Regular expression built using Jeffrey Friedl's example in
# _Mastering Regular Expressions_ (http://www.ora.com/catalog/regexp/).

my $RFC822PAT = <<'EOF';
[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\
xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xf
f\n\015()]*)*\)[\040\t]*)*(?:(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\x
ff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|"[^\\\x80-\xff\n\015
"]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015"]*)*")[\040\t]*(?:\([^\\\x80-\
xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80
-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*
)*(?:\.[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\
\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\
x80-\xff\n\015()]*)*\)[\040\t]*)*(?:[^(\040)<>@,;:".\\\[\]\000-\037\x8
0-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|"[^\\\x80-\xff\n
\015"]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015"]*)*")[\040\t]*(?:\([^\\\x
80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^
\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040
\t]*)*)*@[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([
^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\
\\x80-\xff\n\015()]*)*\)[\040\t]*)*(?:[^(\040)<>@,;:".\\\[\]\000-\037\
x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|\[(?:[^\\\x80-
\xff\n\015\[\]]|\\[^\x80-\xff])*\])[\040\t]*(?:\([^\\\x80-\xff\n\015()
]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\
x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*(?:\.[\04
0\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\
n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\
015()]*)*\)[\040\t]*)*(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?!
[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|\[(?:[^\\\x80-\xff\n\015\[\
]]|\\[^\x80-\xff])*\])[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\
x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\01
5()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*)*|(?:[^(\040)<>@,;:".
\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]
)|"[^\\\x80-\xff\n\015"]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015"]*)*")[^
()<>@,;:".\\\[\]\x80-\xff\000-\010\012-\037]*(?:(?:\([^\\\x80-\xff\n\0
15()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][
^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)|"[^\\\x80-\xff\
n\015"]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015"]*)*")[^()<>@,;:".\\\[\]\
x80-\xff\000-\010\012-\037]*)*<[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?
:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-
\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*(?:@[\040\t]*
(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015
()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()
]*)*\)[\040\t]*)*(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\0
40)<>@,;:".\\\[\]\000-\037\x80-\xff])|\[(?:[^\\\x80-\xff\n\015\[\]]|\\
[^\x80-\xff])*\])[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\
xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*
)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*(?:\.[\040\t]*(?:\([^\\\x80
-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x
80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t
]*)*(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\
\[\]\000-\037\x80-\xff])|\[(?:[^\\\x80-\xff\n\015\[\]]|\\[^\x80-\xff])
*\])[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x
80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80
-\xff\n\015()]*)*\)[\040\t]*)*)*(?:,[\040\t]*(?:\([^\\\x80-\xff\n\015(
)]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\
\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*@[\040\t
]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\0
15()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015
()]*)*\)[\040\t]*)*(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(
\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|\[(?:[^\\\x80-\xff\n\015\[\]]|
\\[^\x80-\xff])*\])[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80
-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()
]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*(?:\.[\040\t]*(?:\([^\\\x
80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^
\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040
\t]*)*(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".
\\\[\]\000-\037\x80-\xff])|\[(?:[^\\\x80-\xff\n\015\[\]]|\\[^\x80-\xff
])*\])[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\
\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x
80-\xff\n\015()]*)*\)[\040\t]*)*)*)*:[\040\t]*(?:\([^\\\x80-\xff\n\015
()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\
\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*)?(?:[^
(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-
\037\x80-\xff])|"[^\\\x80-\xff\n\015"]*(?:\\[^\x80-\xff][^\\\x80-\xff\
n\015"]*)*")[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|
\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))
[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*(?:\.[\040\t]*(?:\([^\\\x80-\xff
\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\x
ff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*(
?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\
000-\037\x80-\xff])|"[^\\\x80-\xff\n\015"]*(?:\\[^\x80-\xff][^\\\x80-\
xff\n\015"]*)*")[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\x
ff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)
*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*)*@[\040\t]*(?:\([^\\\x80-\x
ff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-
\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)
*(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\
]\000-\037\x80-\xff])|\[(?:[^\\\x80-\xff\n\015\[\]]|\\[^\x80-\xff])*\]
)[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-
\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\x
ff\n\015()]*)*\)[\040\t]*)*(?:\.[\040\t]*(?:\([^\\\x80-\xff\n\015()]*(
?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]*(?:\\[^\x80-\xff][^\\\x80
-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)*\)[\040\t]*)*(?:[^(\040)<
>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x8
0-\xff])|\[(?:[^\\\x80-\xff\n\015\[\]]|\\[^\x80-\xff])*\])[\040\t]*(?:
\([^\\\x80-\xff\n\015()]*(?:(?:\\[^\x80-\xff]|\([^\\\x80-\xff\n\015()]
*(?:\\[^\x80-\xff][^\\\x80-\xff\n\015()]*)*\))[^\\\x80-\xff\n\015()]*)
*\)[\040\t]*)*)*>)
EOF

$RFC822PAT =~ s/\n//g;


sub _default_parser {
    my ( $raw ) = @_;
    my %data;    
    
    # получаем данные в виде ключ => значение
    for my $line ( split /\n/, $raw ) {

        chomp $line;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;

        my ( $key, $value ) = $line =~ /^\s*([a-z0-9-]+):\s*(.+)\s*$/;
        next if  !$line || !$value;

        # если полей с одинаковым ключем несколько, пихаем в массив
        $data{$key} = ref $data{$key} eq 'ARRAY' ? 
            [ @{$data{$key}}, $value ] : [ $value ];

    }

    # поиск вообще всех emails
    my @emails = $raw =~ /($RFC822PAT)/gso;
    @emails = map { $_ =~ s/\s+//g; ($_) } @emails;
    $data{emails} = exists $data{emails} ? 
        [ @{$data{emails}}, @emails ] : [@emails];
   
    \%data;
}


1;

=head1 NAME

Net::Whois::Parser - module for parsing whois information

=head1 SYNOPSIS

    use Net::Whois::Parser;
    
    my $info = parse_whois( domain => $domain );
    my $info = parse_whois( raw => $whois_raw_text, domain => $domain  );
    my $info = parse_whois( raw => $whois_raw_text, server => $whois_server  );
    
    $info = {
        nameservers => [
            { domain => 'ns.example.com', ip => '123.123.123.123' },
            { domain => 'ns.example.com' },
        ],
        emails => [ 'admin@example.com' ],
        domain => 'example.com',
        somefield1 => 'value',
        somefield2 => [ 'value', 'value2' ],
        ...
    };
    
    # Your own parsers
    
    sub my_parser {
        my ( $text ) = @_;
        return {
            nameservers => [
                { domain => 'ns.example.com', ip => '123.123.123.123' },
                { domain => 'ns.example.com' },
            ],
            emails => [ 'admin@example.com' ],
            somefield => 'value',
            somefield2 => [ 'value', 'value2' ],
        };                    
    }
    
    $Net::Whois::Parser::PARSERS{'whois.example.com'} = \&my_parser;
    $Net::Whois::Parser::PARSERS{'DEFAULT'}           = \&my_default_parser;
    
    
    # If you want to convert some field name to another:
        
    $Net::Whois::Parser::FIELD_NAME_CONV{'Domain name'} = 'domain';
    
=head1 DESCRIPTION

Net::Whois::Parser module provides Whois data parsing.
You can add your own parsers for any whois server.

=head1 FUNCTIONS

=over 3

=item parse_whois(%args)

Returns hash of whois data. Arguments:
 
C<'domain'> - 
    domain

C<'raw'> -
    raw whois text
 
C<'server'> - 
   whois server 

C<'which_whois'> - 
    option for Net::Whois::Raw::whois. Default value is QRY_ALL

=head1 CHANGES

See file "Changes" in the distribution

=head1 AUTHOR

Ivan Sokolov, C<< <ivsokolov@cpan.org> >>

=head1 COPYRIGHT & LICENSE

Copyright 2009 Ivan Sokolov

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut
