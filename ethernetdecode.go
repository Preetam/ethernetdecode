package ethernetdecode

import (
	"bytes"
	"encoding/binary"
	"net"
)

type EthernetHeader struct {
	Source      net.HardwareAddr
	Destination net.HardwareAddr
	VlanTag     uint32
	EtherType   uint16
}

type IpHeader interface {
	IpVersion() int
}

type Ipv4Header struct {
	VersionAndHeaderLen uint8
	Tos                 uint8
	Len                 uint16
	Id                  uint16
	FragOff             uint16
	Ttl                 uint8
	Protocol            uint8
	Checksum            uint16
	Source              [4]byte
	Destination         [4]byte
}

func (h Ipv4Header) IpVersion() int {
	return 4
}

type Ipv6Header struct {
	VersionTrafficClassFlowLabel uint32
	PayloadLength                uint16
	NextHeader                   uint8
	HopLimit                     uint8
	Source                       [16]byte
	Destination                  [16]byte
}

func (h Ipv6Header) IpVersion() int {
	return 6
}

type Protocol uint8

const (
	ProtocolTcp Protocol = 6
	ProtocolUdp Protocol = 17
)

type ProtocolHeader interface {
	Protocol() Protocol
}

type UdpHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
}

func (h UdpHeader) Protocol() Protocol {
	return ProtocolUdp
}

type TcpHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	SeqNum          uint32
	AckNum          uint32
	OffsetReserved  uint8
	Flags           uint8
	WindowSize      uint16
	Checksum        uint16
	UrgentPointer   uint16
}

func (h TcpHeader) Protocol() Protocol {
	return ProtocolTcp
}

// Decode decodes an ethernet frame header and returns
// an IP header and a TCP or UDP header.
func Decode(header []byte) (EthernetHeader, IpHeader, ProtocolHeader) {
	ethhdr := EthernetHeader{
		Source:      net.HardwareAddr(header[0:6]),
		Destination: net.HardwareAddr(header[6:12]),
	}

	// Check for IPv4
	if header[12] == 0x8 && header[13] == 0x0 {

		ethhdr.EtherType = 0x0800

		iphdr := Ipv4Header{}
		binary.Read(bytes.NewBuffer(header[14:]), binary.BigEndian, &iphdr)

		if iphdr.Protocol == 6 {
			tcphdr := TcpHeader{}
			binary.Read(bytes.NewBuffer(header[34:]), binary.BigEndian, &tcphdr)
			return ethhdr, iphdr, tcphdr
		}

		if iphdr.Protocol == 17 {
			udphdr := UdpHeader{}
			binary.Read(bytes.NewBuffer(header[34:]), binary.BigEndian, &udphdr)
			return ethhdr, iphdr, udphdr
		}
	}

	// Check for IPv6
	if header[12] == 0x86 && header[13] == 0xDD {
		ethhdr.EtherType = 0x86DD

		iphdr := Ipv6Header{}
		binary.Read(bytes.NewBuffer(header[14:]), binary.BigEndian, &iphdr)

		if iphdr.NextHeader == 6 {
			tcphdr := TcpHeader{}
			binary.Read(bytes.NewBuffer(header[54:]), binary.BigEndian, &tcphdr)
			return ethhdr, iphdr, tcphdr
		}

		if iphdr.NextHeader == 17 {
			udphdr := UdpHeader{}
			binary.Read(bytes.NewBuffer(header[54:]), binary.BigEndian, &udphdr)
			return ethhdr, iphdr, udphdr
		}
	}

	return ethhdr, nil, nil
}
