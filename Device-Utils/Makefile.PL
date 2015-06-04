use 5.006;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Device::Utils',
    AUTHOR           => q{Rob Woodward <robwwd@gmail.com>},
    VERSION_FROM     => 'lib/Device/Utils.pm',
    ABSTRACT_FROM    => 'lib/Device/Utils.pm',
    LICENSE          => 'Artistic_2_0',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
		'Mail::Sender'						=> 0.8.21,
		'Params::Validate'					=> 0,
		'Text::Trim'						=> 0,
		'Log::Dispatch'						=> 0,
		'Log::Dispatch::Screen'				=> 0,
		'Log::Dispatch::FileShared'			=> 1.03,
		'Log::Dispatch::Log::Syslog::Fast'	=> 1.03
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Device-Utils-*' },
);
