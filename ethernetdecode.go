package ethernetdecode

import (
	"bytes"
	"encoding/binary"
	"net"
)

type HardwareAddrs struct {
	Source      net.HardwareAddr
	Destination net.HardwareAddr
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
func Decode(header []byte) (HardwareAddrs, IpHeader, ProtocolHeader) {
	hwaddr := HardwareAddrs{
		Source:      net.HardwareAddr(header[0:6]),
		Destination: net.HardwareAddr(header[6:12]),
	}

	// Check for IPv4
	if header[12] == 8 && header[13] == 0 {
		iphdr := Ipv4Header{}
		binary.Read(bytes.NewBuffer(header[14:]), binary.BigEndian, &iphdr)

		if iphdr.Protocol == 6 {
			tcphdr := TcpHeader{}
			binary.Read(bytes.NewBuffer(header[34:]), binary.BigEndian, &tcphdr)
			return hwaddr, iphdr, tcphdr
		}

		if iphdr.Protocol == 17 {
			udphdr := UdpHeader{}
			binary.Read(bytes.NewBuffer(header[34:]), binary.BigEndian, &udphdr)
			return hwaddr, iphdr, udphdr
		}
	}

	return hwaddr, nil, nil
}
