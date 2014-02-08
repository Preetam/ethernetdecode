package ethernetdecode

import (
	"testing"
)

func TestUdp(t *testing.T) {
	header := []byte{
		0, 208, 1, 255, 88, 0, 0, 22, 60, 194, 169,
		171, 8, 0, 69, 0, 1, 44, 0, 0, 64, 0, 64, 17,
		209, 88, 199, 58, 161, 150, 197, 161, 57, 246,
		200, 213, 38, 0, 1, 24, 166, 23,
	}

	_, iphdr, _ := Decode(header)
	if iphdr.IpVersion() != 4 {
		t.Errorf("Expected IPv%d header, got IPv%d", 4, iphdr.IpVersion())
	}
}
