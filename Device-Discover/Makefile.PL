use 5.006;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Device::Discover',
    AUTHOR           => q{Rob Woodward <robwwd@gmail.com>},
    VERSION_FROM     => 'lib/Device/Discover.pm',
    ABSTRACT_FROM    => 'lib/Device/Discover.pm',
    LICENSE          => 'Artistic_2_0',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.010,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
		'Params::Validate'					=> 0,
		'Scalar::Util'						=> 0,
		'List::MoreUtils'					=> 0
        #'ABC'              => 1.6,
        #'Foo::Bar::Module' => 5.0401,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Device-Discover-*' },
);
