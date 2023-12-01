package main

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"io"
	"log"
	"net"
	"strconv"
	"time"
	"fmt"
)

// Scanner represents a ICMP scanner. It contains a pcap handle and
// other information that is needed to scan the network.
type Scanner struct {
	// iface is the interface to send packets on.
	iface *net.Interface
	// gw and src are the gateway and source IP addresses of the
	// interface we're scanning.
	gw, src          net.IP
	gwHardwareAddr   *net.HardwareAddr
	srcPort, dstPort int
	// handle is the pcap handle that we use to receive packets.
	handle *pcap.Handle
	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

// NewScanner creates a new Scanner.
func NewScanner() *Scanner {
	s := &Scanner{
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}
	router, err := routing.New()
	if err != nil {
		log.Fatal(err)
	}
	// figure out the route by using the IP.
	iface, gw, src, err := router.Route(net.ParseIP("114.114.114.114"))
	if err != nil {
		log.Fatal(err)
	}
	s.gw, s.src, s.iface = gw, src, iface
	// open the handle for reading/writing.
	handle, err := pcap.OpenLive(iface.Name, 100, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	s.handle = handle
	gwHwAddr, err := s.getHwAddr()
	if err != nil {
		log.Fatal(err)
	}
	s.gwHardwareAddr = &gwHwAddr
	log.Printf("scanning with interface %v, gateway %v, src %v, hwaddr: %v", iface.Name, gw, src, gwHwAddr)
	return s
}

func main() {
	scan := NewScanner()
	input  := make(chan []string)
	connOutput,_ := scan.Scan(input)
	input <- []string{"192.168.31.78"}
	ipStr := <- connOutput
	fmt.Printf("out:%s\n",ipStr)
}
func (s *Scanner) getHwAddr() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := s.gw
	//prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	// send a single ARP request packet (we never retry a send)
	if err := s.sendPackets(&eth, &arp); err != nil {
		return nil, err
	}
	// wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

// sendPackets sends a packet with the given layers.
func (s *Scanner) sendPackets(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

// Scan scans the network for open TCP ports.
func (s *Scanner) Scan(input chan []string) (connOutput, portOpenOutput chan string) {
	connOutput = make(chan string, 1024)
	portOpenOutput = make(chan string, 1024)
	go s.recv(connOutput, portOpenOutput)
	go s.send(input)
	return connOutput, portOpenOutput
}

// send sends packets to the network.
func (s *Scanner) send(input chan []string) error {
	for ips := range input {
		for _, ip := range ips {
			dstIP := net.ParseIP(ip)
			if dstIP == nil {
				continue
			}
			dstIP = dstIP.To4()
			if dstIP == nil {
				continue
			}
			// construct all the network layers we need.
			eth := layers.Ethernet{
				SrcMAC:       s.iface.HardwareAddr,
				DstMAC:       *s.gwHardwareAddr,
				EthernetType: layers.EthernetTypeIPv4,
			}
			ip4 := layers.IPv4{
				SrcIP:    s.src,
				DstIP:    dstIP.To4(),
				Version:  4,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
			}
			tcp := layers.TCP{
				SrcPort: layers.TCPPort(s.srcPort),
				DstPort: layers.TCPPort(s.dstPort),
				SYN:     true,
			}
			tcp.SetNetworkLayerForChecksum(&ip4)
			err := s.sendPackets(&eth, &ip4, &tcp)
			if err != nil {
				log.Println(err)
			}
		}
	}
	return nil
}

// 接收数据的时候，我们区分TCP+ACK包和RST包:
func (s *Scanner) recv(connOutput, portOpenOutput chan string) {
	defer close(connOutput)
	defer close(portOpenOutput)
	s.handle.SetBPFFilter("dst port " + strconv.Itoa(s.srcPort) + " and dst host " + s.src.To4().String())
	for {
		// read in the next packet.
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if errors.Is(err, io.EOF) {
			// log.Infof("error reading packet: %v", err)
			return
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			continue
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		// find the packets we care about, and print out logging
		// information about them.  All others are ignored.
		if net := packet.NetworkLayer(); net == nil {
			// log.Info("packet has no network layer")
			continue
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer == nil {
			// log.Info("packet has not ip layer")
			continue
		} else if ip, ok := ipLayer.(*layers.IPv4); !ok {
			continue
		} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
			// log.Info("packet has not tcp layer")
		} else if tcp, ok := tcpLayer.(*layers.TCP); !ok {
			continue
		} else if tcp.DstPort != layers.TCPPort(s.srcPort) {
			// log.Infof("dst port %v does not match", tcp.DstPort)
		} else if tcp.RST {
			select {
			case connOutput <- ip.SrcIP.String():
			default:
			}
		} else if tcp.SYN && tcp.ACK {
			select {
			case portOpenOutput <- ip.SrcIP.String():
			default:
			}
		} else {
			log.Printf("ignoring useless packet")
		}
	}
}
