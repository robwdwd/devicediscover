package Device::Discover;

use 5.006;
use strict;
use warnings FATAL => 'all';

use Errno qw(EAGAIN EWOULDBLOCK);

use Carp;

use Params::Validate qw( validate SCALAR UNDEF );
use IO::Socket::INET;
use Net::SNMP;

use List::MoreUtils qw (any firstval);

use Data::Dumper;

=head1 NAME

Device::Discover - Network device discovery module.

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

Device discovery module. Get's device managment protocol, either ssh or telnet
and discoveres the software running on the device using SNMP sysDesc.

	use Device::Discover;

	my $name = '192.168.1.1';

	$device = Device::Discover->new(hostname		=> $name,
										 ssh_os_ignore	=> 'VRP,OneOS',
										 community		=> 'public',
										 snmptimeout	=> 1,
										 snmpversion	=> 2,
										 debug			=> 1);

	my $d = $device->discover;

	if ($device->has_error) {
		print STDERR "ERROR: " . $device->errormsg . ".\n";
	} else {
		print $d->{'hostname'} . "\n";
		print $d->{'software'} . "\n";
		print $d->{'protocol'} . "\n";
	}

	...

=head1 SUBROUTINES/METHODS

=head2 new

Creates new Net::Device Discover::Object.

	$device = Device::Discover->new(
										hostname		=> $hostname,
										[software		=> $software,]
										[protocol		=> $protocol,]
										[ssh_os_ignore	=> $ssh_os_ignore,]
										[snmpversion	=> $snmpversion,]
										[community		=> $community,]
										[snmpusername	=> $snmpusername,]
										[snmppassword	=> $snmppassword,]
										[snmptimeout	=> $snmptimeout,]
										[debug			=> $debug]
										);

This is the constructor for Device::Discover A new object is
returned on success.

The first parameter, or "hostname" argument, is required.

One of the software, community or snmpusername/snmppassword arguments
must be passed. If you set software then no SNMP discovery of
the software running on the device will be done. If you want to discover
the device software then set the community argument or the
snmpusername/snmppassword arguments. Setting both will have the same
effect as just passing the software argument without a community or
snmpusername/snmppassword arguments.

If the protocol argument is set then no discovery of the CLI managment
protocol will be done.

It makes no sense to set the protocol and software arguments, if you
already know both of these you don't need this module.

snmpversion by default is set to 2 for snmp v2c. If you set this to 2
then you only need pass the community argument. For version 3 you must
give the snmpusername and snmppasswords.

snmptimeout defaults to 1 second.

ssh_os_ignore argument takes a comma seperated string os software names
to ignore when checking for SSH. This saves time when you know certain
software running on devices is not capable of running ssh but might allow
connections on the ssh port (only to send an error back down the connection.)

=cut

sub new {
	my $class = shift;
	my %options = @_;

	my $self = {
		has_err => 0,
		errormsg => undef,
		result => {},
		options => {}
	};
	bless($self, $class);

	$self->{'options'} = $self->_init(%options);

	#print Dumper $self;

	return($self);
}


=head2 get_management_protocol

Get's the devices managment protocol, either SSH or Telnet. Returns 0 if
the device does not have telnet or SSH port open or the device closes
the connection once connected.

=cut

sub get_management_protocol {

	my $self = shift;
	
	my $ip_addr = inet_aton $self->{'result'}->{'hostname'} or do {
		$self->_set_errormsg (sprintf ("[%s] [%s] [Failed to discover CLI managment protocol.] [Unknown hostname or IP address: %s]", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}, $self->{'result'}->{'hostname'}));
		return 0;
	};

	return 'SSH' if $self->_check_ssh;
	return 'TELNET' if $self->_check_telnet;

	# Set error message and include the current error from the underlying
	# managment protocol check.

	$self->_set_errormsg (sprintf ("[%s] [%s] [Failed to discover CLI managment protocol.] [%s]", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}, $self->{'errormsg'}));

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

	$self->_set_errormsg (sprintf ("[%s] [Unable to discover software running on device.]", $self->{'result'}->{'hostname'}));
	return 0;
}

=head2 get_sysdesc

Connects to device with snmp and gets sysDesc and lldpDesc.

=cut

sub get_sysdesc {

	my $self = shift;

	my $sysDesc	  = '1.3.6.1.2.1.1.1.0';
	my $lldpDesc  = '1.0.8802.1.1.2.1.3.4.0';
	my $session;
	my $error;

	if ($self->{'options'}->{'snmpversion'} == 3) {
		($session, $error) = Net::SNMP->session(	Hostname => $self->{'options'}->{'hostname'},
													Version => $self->{'options'}->{'snmpversion'},
													Username => $self->{'options'}->{'snmpusername'},
													Authpassword => $self->{'options'}->{'snmppassword'},
													Timeout => $self->{'options'}->{'snmptimeout'});
	} else {
		($session, $error) = Net::SNMP->session(	Hostname => $self->{'options'}->{'hostname'},
													Version => $self->{'options'}->{'snmpversion'},
													Community => $self->{'options'}->{'community'},
													Timeout => $self->{'options'}->{'snmptimeout'});
	}

	if (defined $session) {
		my $result = $session->get_request( Varbindlist => [$sysDesc, $lldpDesc]);

		if (defined($result)) {
			$session->close;

			my $line = $result->{$sysDesc} . " " . $result->{$lldpDesc};

			$self->{'result'}->{'sysdesc'} = $line;
			$line =~ s/\r|\n/ /g;
			printf ("DEBUG:	 [Device::Discover] [SNMP] [%s] [%s]\n", $self->{'result'}->{'hostname'}, $line) if $self->{'options'}->{'debug'};

			return 1;
		} else {
			$self->_set_errormsg (sprintf ("[%s] [SNMP] [%s]", $self->{'result'}->{'hostname'}, $session->error));
		}
		$session->close;
	} else {
		$self->_set_errormsg (sprintf ("[%s] [SNMP] [%s]", $self->{'result'}->{'hostname'}, $error));
	}
	return 0;
}

=head2 discover

Discovers the device. If software isn't given as an argument it will
connect via SNMP to get the device software.

Returns a reference to the results hash with the device name/ip,
software, SNMP sysDesc and managment protocol.

=cut

sub discover {

	my $self = shift;

	my $hostname = $self->{'result'}->{'hostname'};

	unless (defined $self->{'options'}->{'software'}) {

		unless ($self->get_sysdesc()) {
			$self->{'has_error'} = 1;
			return 0;
		};

		if (my $software = $self->parse_sysdesc()) {
			printf ("Device::Discover DEBUG: [%s] [Discovered device is running %s as it's software.]\n", $self->{'result'}->{'hostname'}, $software) if $self->{'options'}->{'debug'};
			$self->{'result'}->{'software'} = $software;
		} else {
			$self->{'has_error'} = 1;
			return 0;
		}
	} else {
		$self->{'result'}->{'software'} = $self->{'options'}->{'software'};
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
				software => {
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
				community => {
					type	=> SCALAR,
					optional => 1,
				},
				snmpversion => {
					type	=> SCALAR,
					default => 2,
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

		}
	);

	if (not defined $p{'software'}) {
		if ($p{'snmpversion'} == 2 and not defined $p{'community'}) {
			croak "Device::Discover, community argument must be passed when snmpversion argument set to 2 (default) and no software argument passed.";
		}

		if ($p{'snmpversion'} == 3 and (not defined $p{'snmpusername'} or not defined $p{'snmppassword'})) {
			croak "Device::Discover, snmpusername and snmppassword arguments must be passed (and not undef) when snmpversion argument set to 3 and no software argument passed.";
		}

	}

	if (defined $p{'software'} and defined $p{'protocol'}) {
		croak "Device::Discover, passing the software and protocol arguments just adds overhead to your script, there's nothing to discover if you know these already.";
	}

	$self->{'result'}->{'hostname'} = $p{hostname};

	return \%p;
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

If ssh_os_ignore is set and software is already discovered or set in
options then software is checked against ignore array to determine
if ssh should be ignored for this device.

=cut

sub _check_ssh {
	my $self = shift;

	# Check if SSH should be ignored.
	#
	if (defined $self->{'result'}->{'software'} and defined $self->{'options'}->{'ssh_os_ignore'} and any {$self->{'result'}->{'software'} eq $_} (split ',', $self->{'options'}->{'ssh_os_ignore'})) {
		printf ("DEBUG:	 [Device::Discover] [%s] [%s] [Ignoring SSH for this device.]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}) if $self->{'options'}->{'debug'};
		return 0;
	}
	
	my $sock = IO::Socket::INET->new(	PeerAddr	=> $self->{'result'}->{'hostname'},
										PeerPort	=> 22,
										Proto		=> 'tcp',
										Timeout		=> 4);
									
	unless ($sock) {
		printf ("DEBUG:	 [Device::Discover] [SSH Check] [%s] [%s] [%s]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}, $!) if $self->{'options'}->{'debug'};
		$self->_set_errormsg ($!); 
		return 0;
	}
	
	my $line;
	
	do {
		
		my $buf = "";
		$line = "";
		
		do  {
			
			my $s = IO::Select->new($sock);
			my @ready = $s->can_read;

			my $bytes_read = sysread($sock, $buf, 1);

			if (not defined $bytes_read) {
				next if $! == EAGAIN || $! == EWOULDBLOCK;
				printf ("DEBUG:	 [Device::Discover] [SSH Check] [%s] [%s] [Socket Error] [%s]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}, $!) if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("Socket Error:" . $!);
				return 0;
			} elsif ($bytes_read == 0) {
				printf ("DEBUG:	 [Device::Discover] [SSH Check] [%s] [%s] [Remote host closed connection]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}) if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("Remote host closed connection");
				return 0;
			}
			
			$line .= $buf;
		   
			if (substr($line, 0, 4) eq "SSH-" and length($line) > 255) {
				printf ("DEBUG:	 [Device::Discover] [SSH Check] [%s] [%s] [SSH Version line too long]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}) if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("SSH Version line too long");
				return 0;
			}
			
			if (length($line) > 4*1024) {
				printf ("DEBUG:	 [Device::Discover] [SSH Check] [%s] [%s] [SSH Pre-version line too long]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}) if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("SSH Pre-version line too long");
				return 0;
			}
			
		} while ($buf ne "\n");
		
	} while (substr($line, 0, 4) ne "SSH-");
    
	$line =~ s/\cM?\n$//;
    
    printf ("DEBUG:	 [Device::Discover] [SSH Check] [%s] [%s] Found SSH remote version string: [%s]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}, $line)  if $self->{'options'}->{'debug'};
    	
    my ($remote_major, $remote_minor, $remote_version) = $line =~ /^SSH-(\d+)\.(\d+)-([^\n]+)$/;
    
    printf ("DEBUG:	 [Device::Discover] [SSH Check] [%s] [%s] Remote protocol version %s.%s, remote software version %s\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}, $remote_major, $remote_minor, $remote_version) if $self->{'options'}->{'debug'};
    
    syswrite $sock, $line . "\n";
    
    my $buf;
    
    my $bytes_read = sysread($sock, $buf, 1);
    
    print STDERR "BUFF: $buf\n";
    
    if (not defined $bytes_read) {
				printf ("DEBUG:	 [Device::Discover] [SSH Check] [%s] [%s] [Socket Error] [%s]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}, $!) if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("Socket Error:" . $!);
				return 0;
	} elsif ($bytes_read == 0) {
				printf ("DEBUG:	 [Device::Discover] [SSH Check] [%s] [%s] [Remote host closed connection]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}) if $self->{'options'}->{'debug'};
				$self->_set_errormsg ("Remote host closed connection");
				return 0;
	}
	
	printf ("DEBUG:	 [Device::Discover] [SSH Check] [%s] [%s] Found SSH running on this device.\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}) if $self->{'options'}->{'debug'};
	
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
		printf ("DEBUG:	 [Device::Discover] [Telnet Check] [%s] [%s] [%s]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}, $!) if $self->{'options'}->{'debug'};
		$self->_set_errormsg ($!); 
		return 0;
	}
	
	my $buf;

	my $s = IO::Select->new($sock);
	my @ready = $s->can_read;

	my $bytes_read = sysread($sock, $buf, 1);

	if (not defined $bytes_read) {
		next if $! == EAGAIN || $! == EWOULDBLOCK;
		printf ("DEBUG:	 [Device::Discover] [Telnet Check] [%s] [%s] [Socket Error] [%s]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}, $!) if $self->{'options'}->{'debug'};
		$self->_set_errormsg ("Socket Error:" . $!);
		return 0;
	} elsif ($bytes_read == 0) {
		printf ("DEBUG:	 [Device::Discover] [Telnet Check] [%s] [%s] [Remote host closed connection]\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}) if $self->{'options'}->{'debug'};
		$self->_set_errormsg ("Remote host closed connection");
		return 0;
	}
	
	printf ("DEBUG:	 [Device::Discover] [Telnet Check] [%s] [%s] Found Telnet running on this device.\n", $self->{'result'}->{'hostname'}, $self->{'result'}->{'software'}) if $self->{'options'}->{'debug'};
	
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
