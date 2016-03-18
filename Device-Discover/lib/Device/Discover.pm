package Device::Discover;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Errno qw(EAGAIN EWOULDBLOCK);
use Carp;
use Scalar::Util qw(blessed );

use Params::Validate qw( validate SCALAR UNDEF OBJECT );
use IO::Socket::INET;

use List::MoreUtils qw (any firstval);

use Time::Piece;

=head1 NAME

Device::Discover - Network device discovery module.

=head1 VERSION

Version 0.03

=cut

our $VERSION = '0.03';


=head1 SYNOPSIS

Device discovery module. Get's device managment protocol, either ssh or telnet
and discoveres the os (operating system) running on the device using SNMP sysDesc.

	use Device::Discover;

	my $name = '192.168.1.1';

	$device = Device::Discover->new(hostname		=> $name,
										 ssh_os_ignore	=> 'VRP,OneOS',
										 community		=> 'public',
										 snmptimeout	=> 1,
										 debug			=> 1);

	my $d = $device->discover;

	if ($device->has_error) {
		print STDERR "ERROR: " . $device->errormsg . ".\n";
	} else {
		print $d->{'hostname'} . "\n";
		print $d->{'os'} . "\n";
		print $d->{'protocol'} . "\n";
	}

	...

=head1 SUBROUTINES/METHODS

=head2 new

Creates new Device::Discover Object.

	$device = Device::Discover->new(
										hostname		=> $hostname,
										[os				=> $os,]
										[protocol		=> $protocol,]
										[ssh_os_ignore	=> $ssh_os_ignore,]
										[community		=> $community,]
										[snmpusername	=> $snmpusername,]
										[snmppassword	=> $snmppassword,]
										[snmptimeout	=> $snmptimeout,]
										[logobj			=> $logobj,]
										[debug			=> $debug]
										);

This is the constructor for Device::Discover A new object is
returned on success.

The first parameter, or "hostname" argument, is required.

One of the os (software), community or snmpusername/snmppassword arguments
must be passed. If you set os then no SNMP discovery of
the os running on the device will be done. If you want to discover
the device os then set the community argument or the
snmpusername/snmppassword arguments. Setting both will have the same
effect as just passing the os argument without a community or
snmpusername/snmppassword arguments.

If the protocol argument is set then no discovery of the CLI managment
protocol will be done.

It makes no sense to set the protocol and os arguments, if you
already know both of these you don't need this module.

snmptimeout defaults to 1 second.

ssh_os_ignore argument takes a comma seperated string os os names
to ignore when checking for SSH. This saves time when you know certain
os running on devices is not capable of running ssh but might allow
connections on the ssh port (only to send an error back down the connection.)

logobj is a reference to a Log::Dispatch object if you want to log output
to Log::Dispatch, this has to be set up first.

=cut

sub new {
	my $class = shift;
	my %options = @_;

	my $self = {
		has_err => 0,
		errormsg => undef,
		logobj	=> undef,
		result => {},
		options => {}
	};
	bless($self, $class);

	$self->{'options'} = $self->_init(%options);
	
	if ((defined $self->{'options'}->{'logobj'} ) and (blessed ($self->{'options'}->{'logobj'}) eq "Log::Dispatch")) {
		$self->{'logobj'} = $self->{'options'}->{'logobj'};
	}

	return($self);
}


=head2 get_management_protocol

Get's the devices managment protocol, either SSH or Telnet. Returns 0 if
the device does not have telnet or SSH port open or the device closes
the connection once connected.

=cut

sub get_management_protocol {

	my $self = shift;
	
	return 'SSH' if $self->_check_ssh;
	return 'TELNET' if $self->_check_telnet;

	# Set error message and include the current error from the underlying
	# managment protocol check.

	$self->_set_errormsg ('[Failed to discover CLI managment protocol.] [' . $self->{'errormsg'} . ']');

	return 0;
}

=head2 parse_sysdesc

Parse SNMP sysDesc string from SNMP and get the OS running on the device.

=cut

sub parse_sysdesc {

	my $self = shift;

	my $descr = $self->{'result'}->{'sysdesc'};

	return 'JunOSe'		if ( $descr =~ m/ERX/);
	return 'OneOS'		if ( $descr =~ m/ONEOS/);
	return 'JunOS'		if ( $descr =~ m/Juniper/);
	return 'EOS'		if ( $descr =~ m/Arista Networks/);
	return 'VRP'		if ( $descr =~ m/Huawei/);
	return 'IOS-XE'		if ( $descr =~ m/IOS-XE/ );
	return 'IOS-XR'		if ( $descr =~ m/IOS XR/ );
	return 'IOS'		if ( $descr =~ m/IOS/ );
	return 'CatOS'		if ( $descr =~ m/catalyst/i );
	return 'css'		if ( $descr =~ m/Content Switch SW/ );
	return 'css-sca'	if ( $descr =~ m/Cisco Systems Inc CSS-SCA-/ );
	return 'pix'		if ( $descr =~ m/Cisco PIX Security Appliance/ );
	return 'asa'		if ( $descr =~ m/Cisco Adaptive Security Appliance/ );
	return 'san-os'		if ( $descr =~ m/Cisco SAN-OS/ );

	$self->_set_errormsg ('Unable to discover os running on device. sysDesc or lldpDesc not parseable: ' . $self->{'result'}->{'sysdesc'} );
	return 0;
}

=head2 get_sysdesc

Connects to device with snmp and gets sysDesc and lldpDesc.

=cut

sub get_sysdesc {
	
	use Net::SNMP;
	
	my $self = shift;

	my $sysDesc	  = '1.3.6.1.2.1.1.1.0';
	my $lldpDesc  = '1.0.8802.1.1.2.1.3.4.0';
	my $session;
	my $error;

	my $community = $self->{'options'}->{'community'};
	
	$community = $self->{'result'}->{'community'} if ($self->{'options'}->{'find_community'});
	
	# First try SNMP v2c
	
	$self->_logger ('debug', 'DEBUG', "[SNMP] Trying SNMP v2c") if $self->{'options'}->{'debug'};
	
	($session, $error) = Net::SNMP->session(	Hostname => $self->{'options'}->{'hostname'},
												Version => 2,
												Community => $community,
												Timeout => $self->{'options'}->{'snmptimeout'});

	

	if (defined $session) {
		my $result = $session->get_request( Varbindlist => [$sysDesc, $lldpDesc]);

		if (defined($result)) {
			$session->close;

			my $line = $result->{$sysDesc} . " " . $result->{$lldpDesc};

			$self->{'result'}->{'sysdesc'} = $line;
			$line =~ s/\r|\n/ /g;
			$self->_logger ('debug', 'DEBUG', "[SNMP] [v2c] [$line]") if $self->{'options'}->{'debug'} >= 2;
	
			return 1;
		} else {
			$self->_logger ('debug', 'DEBUG', '[SNMP] [v2c] ' . $session->error) if $self->{'options'}->{'debug'};
		}
		$session->close;
	} else {
		$self->_logger ('debug', 'DEBUG', '[SNMP] [v2c] ' . $error) if $self->{'options'}->{'debug'};
	}
	
	
	if (defined ($self->{'options'}->{'snmpusername'}) and defined ($self->{'options'}->{'snmppassword'})) {
	
		# Now try SNMPv3
			
		$self->_logger ('debug', 'DEBUG', "[SNMP] Trying SNMP v3") if $self->{'options'}->{'debug'};

		$self->_logger ('debug', 'DEBUG', '[SNMP] [v3] Username: ' . $self->{'options'}->{'snmpusername'} . ', Password: ' .  $self->{'options'}->{'snmppassword'}) if $self->{'options'}->{'debug'} >= 2;	

		($session, $error) = Net::SNMP->session(	Hostname => $self->{'options'}->{'hostname'},
													Version => 3,
													Username => $self->{'options'}->{'snmpusername'},
													Authpassword => $self->{'options'}->{'snmppassword'},
													Timeout => $self->{'options'}->{'snmptimeout'});


		if (defined $session) {
			my $result = $session->get_request( Varbindlist => [$sysDesc, $lldpDesc]);

			if (defined($result)) {
				$session->close;

				my $line = $result->{$sysDesc} . " " . $result->{$lldpDesc};

				$self->{'result'}->{'sysdesc'} = $line;
				$line =~ s/\r|\n/ /g;
				$self->_logger ('debug', 'DEBUG', "[SNMP] [v3] [$line]") if $self->{'options'}->{'debug'} >= 2;
		
				return 1;
			} else {
				$self->_logger ('debug', 'DEBUG', '[SNMP] [v3] ' . $session->error) if $self->{'options'}->{'debug'};
			}
			$session->close;
		} else {
			$self->_logger ('debug', 'DEBUG', '[SNMP] [v3] ' . $error) if $self->{'options'}->{'debug'};
		}
		
	}

	$self->_set_errormsg ('[SNMP] Unable to connect to device with SNMP.');

	return 0;
}


=head2 get_community

Find the community used on this device from community list.

=cut

sub get_community {
	
	use Net::SNMP;
	
	my $self = shift;

	my $sysDesc   = '1.3.6.1.2.1.1.1.0';

	my @community_list = split (',', $self->{'options'}->{'community_list'});

	foreach my $community (@community_list) {

		my ($session, $error) = Net::SNMP->session(Hostname	=> $self->{'options'}->{'hostname'},
													Version		=> 2,
													Community	=> $community,
													Timeout		=> $self->{'options'}->{'snmptimeout'},
													Retries		=> 1
													);

		if (!defined($session)) {
			$self->_set_errormsg ('[Community Discover] ' . $error);
			return 0;
		}

		my $result = $session->get_request( Varbindlist => [$sysDesc] );

		# If there is an snmp response this community works
		# no need to find any others so move on to the next device.
		#
		if (defined($result)) {
			$session->close;
			
			$self->_logger ('debug', 'DEBUG', "[Community Discover] Found community in use on this device: $community") if $self->{'options'}->{'debug'};
			
			$self->{'result'}->{'community'} = $community;
			return 1;
		}
	}

	$self->_set_errormsg ("[Community Discover] Can't find a usable snmp community.");

	return 0;
}

=head2 discover

Discovers the device. If os isn't given as an argument it will
connect via SNMP to get the device os.

Returns a reference to the results hash with the device name/ip,
os, SNMP sysDesc and managment protocol.

=cut

sub discover {

	my $self = shift;

	my $hostname = $self->{'result'}->{'hostname'};
	
	my $ip_addr = inet_aton $self->{'result'}->{'hostname'} or do {
		$self->{'has_error'} = 1;
		$self->_set_errormsg ('Unknown hostname or IP address: ' . $self->{'result'}->{'hostname'});
		return 0;
	};
	
	if ($self->{'options'}->{'find_community'}) {
		unless ($self->get_community()) {
			$self->{'has_error'} = 1;
			return 0;
		};
	}

	unless (defined $self->{'options'}->{'os'}) {

		unless ($self->get_sysdesc()) {
			$self->{'has_error'} = 1;
			return 0;
		};

		if (my $os = $self->parse_sysdesc()) {
			$self->_logger ('debug', 'DEBUG', "Discovered device is running $os as it's operating system.") if $self->{'options'}->{'debug'};
			$self->{'result'}->{'os'} = $os;
		} else {
			$self->{'has_error'} = 1;
			return 0;
		}
	} else {
		$self->{'result'}->{'os'} = $self->{'options'}->{'os'};
	}

	unless (defined $self->{'options'}->{'protocol'}) {

		if (my $protocol = $self->get_management_protocol()) {
			$self->{'result'}->{'protocol'} = $protocol;
		} else {
			$self->{'has_error'} = 1;
			return 0;
		}
	} else {
		$self->{'result'}->{'protocol'} = $self->{'options'}->{'protocol'};
	}

	return $self->{'result'};
}

=head2 has_error

Returns if the object has an error.

=cut

sub has_error {
	my $self = shift;

	return $self->{'has_error'};
}

=head2 errormsg

Returns the last error message. Use has_error to check if a device
has an error, relying on this to return an empty string to check for
errors might produce unexpected results (sometimes non fatal error
messages can be stored here.)

=cut

sub errormsg {
	my $self = shift;
	return $self->{'errormsg'};
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
				hostname => {
					type	=> SCALAR
				},
				os => {
					type	=> SCALAR,
					optional => 1,
					default => undef,
				},
				protocol => {
					type	=> SCALAR,
					optional => 1,
				},
				ssh_os_ignore => {
					type => SCALAR | UNDEF,
					optional => 1
				},
				snmpversion => {
					type	=> SCALAR | UNDEF,
					optional => 1,
				},
				community => {
					type	=> SCALAR,
					optional => 1,
				},
				snmpusername => {
					type	=> SCALAR | UNDEF,
					optional => 1,
					depends	 => ['snmppassword']
				},
				snmppassword => {
					type	=> SCALAR | UNDEF,
					optional => 1,
					depends	 => ['snmpusername'],
				},
				snmptimeout => {
					type	=> SCALAR,
					default => 1
				},
				debug => {
					type	=> SCALAR | UNDEF,
					default => 0
				},
				community_list => {
					type => SCALAR | UNDEF,
					optional => 1
				},
				find_community => {
					type	=> SCALAR | UNDEF,
					default => 0
				},
				logobj => {
					type	=> OBJECT | UNDEF,
					default => undef,
					optional => 1
				},

		}
	);

	if (defined $p{'os'} and defined $p{'protocol'}) {
		croak "Device::Discover, passing the os and protocol arguments just adds overhead to your script, there's nothing to discover if you know these already.";
	}

	$self->{'result'}->{'hostname'} = $p{hostname};

	return \%p;
}

=head2 _logger

Log output such as debugging messages directly, by default send to 
STDOUT, takes the type of error i.e. 'DEBUG', 'ERROR' etc although
this can be anything which is prefixed to output. Adds the hostname
and os (if discovered already) to the line along. $msg is the
error message that will be logged.

=cut

sub _logger {
	
	my $self = shift;
	
	my ($level, $tag, $msg) = @_;
	
	$msg =~ s/\r|\n/ /g;
	
	my $time = gmtime;
	my $dt = '[' . $time->datetime . '+00:00]';
	
	my $pre = '[' . $self->{'result'}->{'hostname'} . ']';
	
	$pre .= ' [' . $self->{'result'}->{'os'} . ']' if (defined $self->{'result'}->{'os'});

	my $message = sprintf ("%s %-7s: [Device::Discover] %s %s\n", $dt, $tag, $pre, $msg);
	
	
	if (defined $self->{'logobj'}) {
		$self->{'logobj'}->log( level => $level, message => $message);
	} else {
		printf $message;
	}
	
	return 1;
}


=head2 _set_errormsg

Accepts string as first agrument and set's it to be the current
error message. Does not set has_error here as we might not want
an error message to cause a failure. i.e a device can fail an ssh
connection but will pass with telnet.

=cut

sub _set_errormsg {

	my $self = shift;
	my $errormsg = shift;

	$self->{'errormsg'} = $errormsg;

	return 1;
}

=head2 _check_ssh

Checks if SSH is available on device.

If ssh_os_ignore is set and os is already discovered or set in
options then os is checked against ignore array to determine
if ssh should be ignored for this device.

=cut

sub _check_ssh {
	my $self = shift;

	# Check if SSH should be ignored.
	#
	if (defined $self->{'result'}->{'os'} and defined $self->{'options'}->{'ssh_os_ignore'} and any {$self->{'result'}->{'os'} eq $_} (split ',', $self->{'options'}->{'ssh_os_ignore'})) {
		$self->_logger ('debug', 'DEBUG', '[SSH Check] Ignoring SSH for this device.') if $self->{'options'}->{'debug'};
		return 0;
	}
	
	my $sock = IO::Socket::INET->new(	PeerAddr	=> $self->{'result'}->{'hostname'},
										PeerPort	=> 22,
										Proto		=> 'tcp',
										Timeout		=> 4);
									
	unless ($sock) {
		$self->_logger ('debug', 'DEBUG', "[SSH Check] $!") if $self->{'options'}->{'debug'};
		$self->_set_errormsg ("[SSH Check] $!"); 
		return 0;
	}
	
	$self->_logger ('debug', 'DEBUG', '[SSH Check] Checking if ssh is available.') if $self->{'options'}->{'debug'};
	
	my $line;
	
	do {
		
		my $buf = "";
		$line = "";
		
		do  {
			
			my $s = IO::Select->new($sock);
			my @ready = $s->can_read(20);
			
			if (!@ready) {
				$self->_logger ('debug', 'DEBUG', "[SSH Check] Failed can_read, seems we can't read anything from the SSH port") if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("[SSH Check] Failed can_read, seems we can't read anything from the SSH port"); 
				$sock->close;
				return 0;
			}

			my $bytes_read = sysread($sock, $buf, 1);

			if (not defined $bytes_read) {
				next if $! == EAGAIN || $! == EWOULDBLOCK;
				$self->_logger ('debug', 'DEBUG', "[SSH Check] Socket Error: $!.") if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("[SSH Check] Socket Error:" . $!);
				$sock->close;
				return 0;
			} elsif ($bytes_read == 0) {
				$self->_logger ('debug', 'DEBUG', '[SSH Check] Remote host closed connection.') if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("[SSH Check] Remote host closed connection");
				$sock->close;
				return 0;
			}
			
			$line .= $buf;
		   
			if (substr($line, 0, 4) eq "SSH-" and length($line) > 255) {
				$self->_logger ('debug', 'DEBUG', '[SSH Check] SSH Version line too long.') if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("[SSH Check] SSH Version line too long");
				$sock->close;
				return 0;
			}
			
			if (length($line) > 4*1024) {
				$self->_logger ('debug', 'DEBUG', '[SSH Check] SSH pre-version line too long.') if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("[SSH Check] SSH Pre-version line too long");
				$sock->close;
				return 0;
			}
			
		} while ($buf ne "\n");
		
	} while (substr($line, 0, 4) ne "SSH-");
    
	$line =~ s/\cM?\n$//;
    
    $self->_logger ('debug', 'DEBUG', "[SSH Check] Found SSH remote version string: $line") if $self->{'options'}->{'debug'};
    
    my ($remote_major, $remote_minor, $remote_version) = $line =~ /^SSH-(\d+)\.(\d+)-([^\n]+)$/;
    
	$self->_logger ('debug', 'DEBUG', "[SSH Check] Remote protocol version $remote_major.$remote_minor, remote software version $remote_version.") if $self->{'options'}->{'debug'};
	
    # Write version string back.
    syswrite $sock, $line . "\n";
    
	# Read more, should be encryption capabilities... 
    my $buf;
    my $bytes_read = sysread($sock, $buf, 8192);
    
    #print STDERR "BUFF: $buf\n";
    
    if (not defined $bytes_read) {
		$self->_logger ('debug', 'DEBUG', "[SSH Check] Socket Error: $!") if $self->{'options'}->{'debug'};
		$self->_set_errormsg ("[SSH Check] Socket Error: $!");
		$sock->close;
		return 0;
	} elsif ($bytes_read == 0) {
		$self->_logger ('debug', 'DEBUG', '[SSH Check] Remote host closed connection.') if $self->{'options'}->{'debug'};
		$self->_set_errormsg ('[SSH Check] Remote host closed connection.');
		$sock->close;
		return 0;
	}
	
	# Found working SSH server. Sometimes doesn't work if host closes the
	# connection after the key exchange, maybe we need to get the login
	# prompt, but that's for another day...
	#
	$self->_logger ('debug', 'DEBUG', '[SSH Check] Found SSH running on this device.') if $self->{'options'}->{'debug'};
	
	$sock->shutdown(2);
	$sock->close;
		
	return 1;

}

=head2 _check_telnet

Checks if Telnet is available on device.

=cut

sub _check_telnet {

	my $self = shift;
	
	my $sock = IO::Socket::INET->new(	PeerAddr	=> $self->{'result'}->{'hostname'},
										PeerPort	=> 23,
										Proto		=> 'tcp',
										Timeout		=> 4);
									
	unless ($sock) {
		$self->_logger ('debug', 'DEBUG', "[Telnet Check] $!") if $self->{'options'}->{'debug'};
		$self->_set_errormsg ($!); 
		return 0;
	}
	
	$self->_logger ('debug', 'DEBUG', '[Telnet Check] Checking if telnet is available.') if $self->{'options'}->{'debug'};
	
	my $buf;

	my $s = IO::Select->new($sock);
	my @ready = $s->can_read(20);
	
	if (!@ready) {
		$self->_logger ('debug', 'DEBUG', "[Telnet Check] Failed can_read, seems we can't read anything from the telnet port") if $self->{'options'}->{'debug'};
		$self->_set_errormsg ("[Telnet Check] Failed can_read, seems we can't read anything from the telnet port"); 
		$sock->close;
		return 0;
	}

	my $bytes_read = sysread($sock, $buf, 1);
	
	$self->_logger ('debug', 'DEBUG', '[Telnet Check] Checking if telnet socket allows us to read a byte of data.') if $self->{'options'}->{'debug'};

	if (not defined $bytes_read) {
		next if $! == EAGAIN || $! == EWOULDBLOCK;
		$self->_logger ('debug', 'DEBUG', "[Telnet Check] Socket Error: $!") if $self->{'options'}->{'debug'};
		$self->_set_errormsg ("[Telnet Check] Socket Error:" . $!);
		$sock->close;
		return 0;
	} elsif ($bytes_read == 0) {
		$self->_logger ('debug', 'DEBUG', '[Telnet Check] Remote host closed connection.') if $self->{'options'}->{'debug'};
		$self->_set_errormsg ("[Telnet Check] Remote host closed connection");
		$sock->close;
		return 0;
	}
	
	$self->_logger ('debug', 'DEBUG', '[Telnet Check] Found Telnet running on this device.') if $self->{'options'}->{'debug'};
	
	$sock->shutdown(2);
	$sock->close;
	
	return 1;
}


=head1 AUTHOR

Rob Woodward, C<< <robwwd at gmail.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-device-discover at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Device-Discover>.	 I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

	perldoc Device::Discover


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Device-Discover>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-Device-Discover>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-Device-Discover>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-Device-Discover/>

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

1; # End of Device::Discover
