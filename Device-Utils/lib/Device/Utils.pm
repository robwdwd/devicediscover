package Device::Utils;

use 5.010;

use strict;
use warnings FATAL => 'all';
use Carp;

use POSIX qw ( ceil ) ;

use Log::Dispatch;
use Log::Dispatch::Screen;
use Log::Dispatch::FileShared;
use Log::Dispatch::Log::Syslog::Fast;

use Params::Validate qw( validate SCALAR UNDEF CODEREF HASHREF);
use Text::Trim;
use Time::Piece;

=head1 NAME

Device::Utils - The great new Device::Utils!

=head1 VERSION

Version 0.06

=cut

our $VERSION = '0.06';


=head1 SYNOPSIS

Various methods for working with seedfiles and network devices. Can
parse seedfiles and return chunks for processing (useful with forks).

Set's up flexible logging using Log::Dispatch.

    use Device::Utils;

  my $dutils =  Device::Utils->new(
                  seedfile    => 'seed.txt',
                  valid_line_sub  => \&parse_line,
                  errorlog    => 'errors.log',
                  faillog      => 'fail.log'
                  );

  my ($queue_size, $processes) = $dutils->fork_counts(5, 10);

  # Create Parallel::ForkManager with number of processes.
  #
  my $pm = Parallel::ForkManager->new($processes);

  while ((my $devices = $dutils->readNlines($queue_size))) {

    $pm->start() and do next; # do the fork

    while (@$devices) {
      my $d = shift @$devices;
      print 'Found device: ' . $d->{'hostname'} . "\n";
    };
    $pm->finish(1);
  }

  $pm->wait_all_children;

  $dutils->close_seedfile(); # Will close when module goes out of scope
                 # but might want to close earlier.

  sub parse_line {
    $line = shift;
    return 0 unless $line; # Empty line

    if (not ($line =~ /^([\d\w\-]+)\.(\w+);([\w-]+)$/)) {
      $dutils->logger ('alert', 'FAILED', "[$line] Seed line in wrong format for device.");
      return 0;
    }

    return {'hostname' => "$1.$2", 'os' => $3, 'city' => $2} ;

  }

=head1 new Device::Utils

  $device = Device::Utils->new(
                [seedfile    => $filename,]
                [valid_line_sub  => $subref,]
                [syslog      => $syslog],
                [mail      => $mailhashref],
                [combined_log  => $combined_log],
                [debuglog    => $options->debuglog],
                [infolog    => $options->infolog],
                [errorlog    => $options->errorlog],
                [faillog    => $options->faillog],
                [quiet      => $options->quiet],
                [debug      => $debug]
                );

Creates a new Device::Utils object. Opens any seed files and set's up
logging.

=head2 Parameters

=head3 seedfile

Filename and full path to seedfile.

=head3 valid_line_sub

A code reference to a subroutine to parse and/or validate a single
line in the seedfile, should return 0 on failure. Return value will
be pushed onto an array in the readNlines method, so should be a
simple scalar or reference. If ommited then the internal _valid_line
method is used which returns a trimed line.

=head3 syslog

Takes a hash reference to syslog servers.

  my $syslog = {
        'localhost' => {
                 'facility' => 'local6',
                 'host' => 'localhost',
                 'port' => '514',
                 'protocol' => 'udp',
                 'severity' => 'err'
               },
        'sysloghost' => {
              'port' => '514',
              'host' => '192.168.1.10',
              'facility' => 'local6',
              'severity' => 'err',
              'protocol' => 'udp'
            }

        ....
      };

=head3 mail

Takes a hash reference with mail sending details.

  my $mail = {
         'server' => 'localhost',
         'subject' => 'Device Failed Log',
         'from' => 'devices@example.net',
         'to' => 'support@example.net',
         'cc' => 'admins@example.net'
      };

=head3 combined_log

File to log all messages from debug to alert.


=head3 debuglog

File to log debugging messages to, anything sent at level 'debug'.

=head3 infolog

File to log informational messages to, anything sent at level 'info' or 'notice'.

=head3 errorlog

File to log error messages to, anything sent at level 'warning' or 'error'.

=head3 faillog

File to log fail messages to, anything sent at level 'critical' or 'alert'.

=head3 quiet

Suppress log output to STDIN and STDERR.

=head3 debug

Set to an integer value above 0 to get some debug output.

=cut

sub new {
  my $class = shift;
  my %options = @_;

  my $self = {
    sfh => undef,
    sf_count => 0,
    vlsubref => undef,
    log => undef,
    options => {}
  };

  bless($self, $class);

  $self->{'options'} = $self->_init(%options);

  # Setup logging
  #
  $self->{'log'} = $self->_setup_logging();

  # Open the seedfile and count the number of lines.
  #
  if ($self->{'options'}->{'seedfile'}) {

    my $fh = $self->_open_seedfile();

    # Get number of lines in file.
    while(<$fh>) {};
    $self->{'sf_count'} = $.;
    seek $fh, 0, 0; # Rewind

    $self->{'sfh'} = $fh;

    $self->logger ('warning', 'WARNING', 'Seedfile contents are empty, this is probably not what you want.') if ($self->{'sf_count'} <= 0);
  }

  # Set valid line code ref here, Params::Validate should check it's
  # actually a coderef.

  if ($self->{'options'}->{'valid_line_sub'}) {
    $self->{'vlsubref'} = $self->{'options'}->{'valid_line_sub'};
  }

  return($self);
}

=head1 SUBROUTINES/METHODS

=head2 fork_counts

  my ($processes, $queue_size) = $dutils->fork_counts(20, 5);

Works out optimal processes and queue size to fork given
the number of lines in the seedfile. Tries to maintain at least a
queue size of three per process if possible.

Returns the number of process and queue size.

=cut

sub fork_counts {

  my $self = shift;
  my ($processes, $queue_size) = @_;

  my $total_lines = $self->{'sf_count'};

  return 0 unless $total_lines;

  $processes = 1 if $processes <= 0; # Can't have 0 or negative processes.

  # Check if the total lines is less than the maximum processes, if so divide
  # by three.
  #
  if ($total_lines < $processes) {
    $processes = ceil  ($total_lines / 3) || 1; # Divide the total lines by 3, if 0 (less than 3 lines) set to 1.
    $self->logger ('notice', 'NOTICE', "Changing process count to be a third of total lines ($total_lines) in seedfile, process count now $processes.");
  }

  # Check if total lines in seedfile divided by number of processes is less
  # than the devices per process, and if so set devices by process to the
  # number of lines divided by process.

  if ($total_lines / $processes < $queue_size) {
    $queue_size = ceil ($total_lines / $processes);

    # If devices per process works out to be one, let's reduce the number
    # of processes further so that devices per process is at least 3.
    #
    if ($queue_size <= 1) {
      $processes = ceil ($processes / 3);
      $queue_size = 3;
      $self->logger ('notice', 'NOTICE', "Changing number of process to maintain a queue size of three, process count now $processes, queue size now 3. Total seed lines $total_lines.");
    } else {
      $self->logger ('notice', 'NOTICE', "Setting queue size to $queue_size (with $processes process) for better performance. Total lines $total_lines / $processes = $queue_size.");
    }

  }

  return ($processes, $queue_size);
}

=head2 readNlines

  readNlines($count)

Takes $count lines as parameter

  while ((my $devices = $dutils->readNlines(10))) {

    $pm->start() and do next; # do the fork
    do_devices($xdevices);
    $pm->finish(1);
  }

Reads N lines from the seedfile and returns them as an array containing
the return value of valid_lines subroutine or sub routine passed by
reference to valid_line_sub.

head3

=cut

sub readNlines {

  my $self = shift;
  my $count = shift;

  my $fh = $self->{'sfh'};
  my $subref = $self->{'vlsubref'};

  my $lines = [];



  unless ($fh) {
    $self->logger ('error', 'ERROR', 'Seedfile not open, returning empty list.');
    return 0;
  }

  while(<$fh>) {

    trim $_;

    my $dev;

    if (defined $subref) {
      $dev = $subref->($_);
    } else {
      $dev = $self->_valid_line($_);
    }

    if ($dev) {
      $self->logger ('debug', 'DEBUG', "[$_] Finished parsing line, adding to queue.") if $self->{'options'}->{'debug'} >= 2;
      push( @$lines, $dev );
    }

    last if @$lines == $count;
  }

  return $lines if @$lines;

  return 0;
}

=head2 logger

Logs formated messages to the log channels.

  $dutils->logger($level, $tag, $msg);

  $dutils->logger($level, $tag, $device, $msg);

The first form logs a message contained in $msg to Log::Dispatch with
$level and $tag prepended to line.

The second form takes a $device hash reference containing at minimum the
'hostname' key and optional 'os' and 'protocol' keys.

  my $device = {'hostname' => 'host', 'os' => 'JunOS', 'protocol' => 'SSH'};


See http://search.cpan.org/~drolsky/Log-Dispatch/lib/Log/Dispatch.pm#LOG_LEVELS for log levels.


=cut

sub logger {

  my $self = shift;

  my ($level, $tag, $device, $msg);

  if (@_ == 3) {
    ($level, $tag, $msg) = @_;
  }

  if (@_ == 4) {
    ($level, $tag, $device, $msg) = @_;
  }

  return 0 unless ($msg); # Message is empty.

  $msg =~ s/\r|\n/ /g;

  my $message;

  my $time = gmtime;

  my $dt = '[' . $time->datetime . '+00:00]';

  if ($device) {

    return 0 unless (ref($device) eq "HASH");

    my $pre = '';

    $pre .= '[' . $device->{'hostname'} . '] '  if (defined $device->{'hostname'});
    $pre .= '[' . $device->{'os'} . '] '     if (defined $device->{'os'});
    $pre .= '[' . $device->{'protocol'} . '] '  if (defined $device->{'protocol'});

    $message = sprintf ("%s %-7s: %s%s\n", $dt, $tag, $pre, $msg);
  } else {
    $message = sprintf ("%s %-7s: %s\n", $dt, $tag, $msg);
  }

  $self->{'log'}->log( level => $level, message => $message);

  return 1;

}

=head2 get_logobj

Returns the Log::Dispatch reference for logging. If you want this module
to set up logging for you but want to send log messages without using
the logger method.

=cut

sub get_logobj {

  my $self = shift;

  return $self->{'log'};

}

=head2 get_sf_count

Returns the total amount of lines found in the seedfile. Will return 0
if the seedfile was not opened (because of an error or you didn't
supply a seedfile to open.) Will also return 0 if you supplied an empty
seedfile.

=cut

sub get_sf_count {

  my $self = shift;

  return $self->{'sf_count'};
}

=head2 close_seedfile

Close the seedfile and clear the internal file handle pointing to the
seedfile. You should do this after you have read and processed all the
lines. If you don't the seedfile is closed when the module goes out of
scope.

=cut

sub close_seedfile {

  my $self = shift;

  if ($self->{'sfh'}) {
    close $self->{'sfh'};
  }

  $self->{'sfh'} = undef;

}

=head2 mail_sender

Sends out the e-mail of the faillog.

=cut

sub mail_sender {

  my $self = shift;

  unless ($self->{'options'}->{'faillog'}) {
    $self->logger ('error', 'ERROR', "Can't mail failed log, faillog is not enabled.");
    return;
  }

  use Email::Stuffer;

  $self->logger ('debug', 'DEBUG', "Sending failed log file email.") if $self->{'options'}->{'debug'};

  my $subject = $self->{'options'}->{'mail'}->{'subject'} || 'Device failure log.';

  eval {

    Email::Stuffer->from($self->{'options'}->{'mail'}->{'from'})
      ->to($self->{'options'}->{'mail'}->{'to'})
      ->subject($subject)
      ->text_body('Failure log is attached')
      ->attach_file($self->{'options'}->{'faillog'})
      ->send_or_die;

  };
  if ($@) {
    $self->logger ('error', 'ERROR', "Failed to send the failed log email: $@");
  }
}


=head1 INTERNAL METHODS

These methods should not be called directly but are used internally
by the module.

=head2 _init

init function to validate arguments, not called directly.

=cut

sub _init {
  my $self = shift;

  my %p = validate(
    @_, {
        total_devices => {
          type  => SCALAR,
          optional => 1,
          default => undef
        },
        seedfile => {
          type  => SCALAR | UNDEF,
          optional => 1,
          default => undef
        },
        valid_line_sub => {
          type  => CODEREF | UNDEF,
          optional => 1
        },
        syslog => {
          type  => HASHREF | UNDEF,
          optional => 1,
          default => undef
        },
        mail => {
          type  => HASHREF | UNDEF,
          optional => 1,
          default => undef
        },
        combined_log => {
          type  => UNDEF | SCALAR,
          optional => 1,
          default => undef
        },
        debuglog => {
          type  => UNDEF | SCALAR,
          optional => 1,
          default => undef
        },
        infolog => {
          type  => UNDEF | SCALAR,
          optional => 1,
          default => undef
        },
        errorlog => {
          type  => UNDEF | SCALAR,
          optional => 1,
          default => undef
        },
        faillog => {
          type  => UNDEF | SCALAR,
          optional => 1,
          default => undef
        },
        quiet => {
          type  => SCALAR | UNDEF,
          default => 0
        },
        debug => {
          type  => SCALAR | UNDEF,
          default => 0
        }
    }
  );

  if (defined $p{'mail'} and not defined $p{'faillog'} ) {
    croak "Device::Utils, mail paramater given but faillog parameter missing.";
  }

  return \%p;
}

=head2 _setup_logging

Sets up logging using Log::Dispatch. By default logs to STDERR and STDOUT,
and optionally syslog and file logs.

Logging levels are:

debug
info
notice
warning
error
critical
alert
emergency

=cut


sub _setup_logging {

  my $self = shift;

  my $log = Log::Dispatch->new();

  # Syslog
  #
  if ($self->{'options'}->{'syslog'}) {

    # Go through each syslog server and add to the log dispatcher.
    #
    foreach (keys %{$self->{'options'}->{'syslog'}}) {

      $log->add (Log::Dispatch::Log::Syslog::Fast->new(
              min_level   => 'debug',
              name    => $_,
              transport  => $self->{'options'}->{'syslog'}->{$_}->{'protocol'},
              facility  => $self->{'options'}->{'syslog'}->{$_}->{'facility'},
              severity  => $self->{'options'}->{'syslog'}->{$_}->{'severity'},
              host    => $self->{'options'}->{'syslog'}->{$_}->{'host'},
              port    => $self->{'options'}->{'syslog'}->{$_}->{'port'}
              )
            );
    }
  }

  # File logging.
  #
  $log->add(
    Log::Dispatch::FileShared->new(
      name      => 'debuglog',
      min_level => 'debug',
      max_level => 'debug',
      filename  => $self->{'options'}->{'debuglog'},
      mode      => '>'
    )
  ) if $self->{'options'}->{'debuglog'};

  $log->add(
    Log::Dispatch::FileShared->new(
      name      => 'infolog',
      min_level => 'info',
      max_level => 'notice',
      filename  => $self->{'options'}->{'infolog'},
      mode      => '>'
    )
  ) if $self->{'options'}->{'infolog'};

  $log->add(
    Log::Dispatch::FileShared->new(
      name      => 'errorlog',
      min_level => 'warning',
      max_level => 'error',
      filename  => $self->{'options'}->{'errorlog'},
      mode      => '>'
    )
  ) if $self->{'options'}->{'errorlog'};


  $log->add(
    Log::Dispatch::FileShared->new(
      name      => 'faillog',
      min_level => 'critical',
      max_level => 'alert',
      filename  => $self->{'options'}->{'faillog'},
      mode      => '>'
    )
  ) if $self->{'options'}->{'faillog'};

  $log->add(
    Log::Dispatch::FileShared->new(
      name      => 'combined_log',
      min_level => 'debug',
      filename  => $self->{'options'}->{'combined_log'},
      mode      => '>'
    )
  ) if $self->{'options'}->{'combined_log'};


  # Screen / CLI
  #
  $log->add(
    Log::Dispatch::Screen->new(
      name      => 'debug_info_stdout',
      min_level => 'debug',
      max_level => 'notice'
    )
  ) unless $self->{'options'}->{'quiet'};

  $log->add(
    Log::Dispatch::Screen->new(
      name      => 'errors_warnings_stderr',
      min_level => 'warning',
      stderr    => 1
    )
  ) unless $self->{'options'}->{'quiet'};

  return $log;
}


sub _valid_line {
  my $self = shift;
  my $line = shift;

  trim $line;

  return $line;
}

sub _open_seedfile {

  my $self = shift;

  if ($self->{'options'}->{'seedfile'}) {
    open SEEDFILE, $self->{'options'}->{'seedfile'} or die "ERROR: Can't open seedfile: $!";
    return *SEEDFILE;
  }

  return undef;

}

sub DESTROY {

  my $self = shift;

  close_seedfile();

}

=head1 AUTHOR

Rob Woodward, C<< <robwwd at gmail.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-device-utils at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Device-Utils>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Device::Utils


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Device-Utils>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Device-Utils>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Device-Utils>

=item * Search CPAN

L<http://search.cpan.org/dist/Device-Utils/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2015 Rob Woodward.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of Device::Utils
