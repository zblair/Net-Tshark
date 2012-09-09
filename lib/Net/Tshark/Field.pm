package Net::Tshark::Field;
use strict;
use warnings;

our $VERSION = '0.01';

use List::MoreUtils qw(any all uniq after);
use List::Util qw(reduce);

use overload (
    q("") => sub {
        my $self = tied %{ $_[0] };
        $self->{__value};
    }
);

sub new
{
    my ($class, $field_data) = @_;
    return if (!defined $field_data);

    # Extract the value, and child nodes of this field
    my $value =
      (defined $field_data->{show})
      ? $field_data->{show}
      : $field_data->{showname};
    my @child_nodes =
      (@{ $field_data->{field} || [] }, @{ $field_data->{proto} || [] });

    # If this node has no children, we can just return a scalar
    return $value if (!@child_nodes);

    # If a field doesn't have a name, give it a name based on
    # its showname or show attribute.
    foreach (@child_nodes)
    {
        if (!defined $_->{name} || !length $_->{name})
        {
            $_->{name} =
              defined $_->{showname} && length($_->{showname}) ? $_->{showname}
              : defined $_->{show} ? $_->{show}
              :                      q();
        }
    }

    my $data = {
        show          => $field_data->{show},
        showname      => $field_data->{showname},
        name          => $field_data->{name},
        size          => $field_data->{size},
        value         => $field_data->{value},
        __value       => $value,
        __child_nodes => \@child_nodes,
    };

    # Tie a new hash to this package so we can access parts of the parsed
    # PDML using hash notation (e.g. $packet->{ip}). Note that the TIEHASH
    # subroutine does the actual construction of the object.
    my $self = {};
    tie %{$self}, $class, $data;
    return bless $self, $class;
}

sub fields
{
    my ($field) = @_;
    my $self = tied %{$field};
    return map { Net::Tshark::Field->new($_) } @{ $self->{__child_nodes} };
}

sub show
{
    my ($field) = @_;
    my $self = tied %{$field};
    return $self->{show};
}

sub showname
{
    my ($field) = @_;
    my $self = tied %{$field};
    return $self->{showname};
}

sub name
{
    my ($field) = @_;
    my $self = tied %{$field};
    return $self->{name};
}

sub size
{
    my ($field) = @_;
    my $self = tied %{$field};
    return $self->{size};
}

sub value
{
    my ($field) = @_;
    my $self = tied %{$field};
    return $self->{value};
}

sub hash
{
    my ($field) = @_;

    my %hash = %{$field};
    while (my ($key, $value) = each %hash)
    {
        if (ref $hash{$key})
        {
            my $sub_hash = $hash{$key}->hash;
            $hash{$key} = $sub_hash;
        }
    }

    return \%hash;
}

sub TIEHASH
{
    my ($class, $self) = @_;
    return bless $self, $class;
}

sub STORE
{

    # Do nothing. If someone tries to access a field that doesn't exist,
    # Perl will try to create it via autovilification. We don't want to
    # create anything, but we also don't want this to trigger any warnings.
}

sub FETCH
{
    my ($self, $key) = @_;
    my @nodes = $self->__fields($key);

    # If nothing was found, do a deep search in the child nodes for a name match
    if (!@nodes)
    {
        foreach my $child (@{ $self->{__child_nodes} })
        {
            push @nodes,
              grep { $_->{name} =~ /^(?:.*\.)?$key$/i }
              (@{ $child->{field} || [] }, @{ $child->{proto} || [] });
        }
    }

    # If all the matching fields are leaves, append all their values and
    # return them as a constructed field
    if (all { !defined $_->{field} && !defined $_->{proto} } @nodes)
    {
        my $show = join(q(),
            map { (defined $_->{show}) ? $_->{show} : $_->{showname} } @nodes);
        return Net::Tshark::Field->new({ show => $show });
    }

    # Otherwise, return the first matching node
    return Net::Tshark::Field->new($nodes[0]);
}

sub EXISTS
{
    my ($self, $key) = @_;
    return any { $_->{name} =~ /^(?:.*\.)?$key$/i } @{ $self->{__child_nodes} };
}

sub DEFINED
{
    return EXISTS(@_);
}

sub CLEAR
{
    warn 'You cannot clear a ' . __PACKAGE__ . ' object';
    return;
}

sub DELETE
{
    warn 'You cannot delete from a ' . __PACKAGE__ . ' object';
    return;
}

sub FIRSTKEY
{
    my ($self) = @_;
    return (@{ $self->{__child_nodes} })[0]->{name};
}

sub NEXTKEY
{
    my ($self, $last_key) = @_;

    # Get a set of all the names of the child nodes, with no repeats
    my @keys = uniq(map { $_->{name} } @{ $self->{__child_nodes} });
    return (after { $_ eq $last_key } (@keys))[0];
}

sub __fields
{
    my ($self, $key) = @_;

    # Message bodies are named differently in different versions of Wireshark
    if ($key eq 'Message body' || $key eq 'msg_body')
    {
        $key = qr/Message body|msg_body/;
    }

    # Find all the fields with a name that matches $key.
    my @matching_nodes =
      grep { $_->{name} =~ /^(?:.*\.)?$key$/i } @{ $self->{__child_nodes} };

    # Choose the shortest matching field name
    my $shortestName = reduce { length($a) < length($b) ? $a : $b }
    map { $_->{name} } @matching_nodes;

    # If there are more than one matching field, choose the
    # field or protocol with the shortest name.
    my @nodes = grep { $_->{name} eq $shortestName } (@matching_nodes);

    return @nodes;
}

1;

__END__

=head1 NAME

Net::Tshark::Field - Represents a field in a packet returned by Net::Tshark.

=head1 SYNOPSIS

  use Net::Tshark;

  # Start the capture process, looking for HTTP packets
  my $tshark = Net::Tshark->new;
  $tshark->start(interface => 2, display_filter => 'http');

  # Do some stuff that would trigger HTTP packets for 30 s
  ...

  # Get any packets captured
  my @packets = $sniffer->get_packets;
  
  # Extract packet information by accessing each packet like a nested hash
  my $src_ip = $packets[0]->{ip}->{src};
  my $dst_ip = $packets[0]->{ip}->{dst};

  # Find all of the HTTP packets captured
  my @http_packets = grep { defined $_->{http} } @packets;

=head1 DESCRIPTION

Represents a field within a packet returned by Net::Tshark->get_packet.

=head2 METHODS

=over 4

=item $tshark->start(%options)

  Parameters:
  interface      - network interface to use (1, 2, etc)
  capture_filter - capture filter, as used by tshark
  display_filter - display filter, as used by tshark
  duration       - maximum number of seconds to capture packets for

=item $tshark->stop

Terminates the tshark process, stopping any further packet capture. You may still execute C<get_packets> after the tshark process has terminated.

=item $tshark->is_running

Returns a true value if the tshark process is running, or a false value if
the tshark process is not running.

=item $tshark->get_packet

Retrieves the next available captured packet, or returns undef if no packets are
available. Packets are C<Net::Tshark::Packet> objects, which implement much of the same interface as native hashes. Therefore, you can dereference C<Net::Tshark::Packet> objects much as you would nested hashes. In fact, you can even cast a C<Net::Tshark::Packet> object to a real hash:

  # Get a packet and access its fields directly
  my $packet = $tshark->get_packet;
  print "The dst IP is $packet->{ip}->{dst}\n";

  # Deep-copy the packet object and store its fields in a native hash
  my %packet_hash = %{$packet->hash};
  print "The src IP is $packet_hash{ip}->{src}\n";

=item $tshark->get_packets

Retrieves all available captured packets, or returns an empty list if no packets
are available.

  # Get a list of the source ips of all captured IP packets
  my @packets = $tshark->get_packets;
  my @src_ips = map { $_->{ip}->{src} } grep { defined $_->{ip} } @packets;
 
=back

=head1 SEE ALSO

Net::Pcap - Interface to pcap(3) LBL packet capture library

=head1 AUTHOR

Zachary Blair, E<lt>zack_blair@hotmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Zachary Blair

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut

