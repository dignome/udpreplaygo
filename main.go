// SPDX-License-Identifier: MIT
// Go rewrite of udpreplay-style logic shown in the C++ snippet.
//
// Build:
//   go mod init udpreplaygo
//   go get github.com/google/gopacket@latest
//   go build -o udpreplaygo .
// Run:
//   sudo ./udpreplaygo -i eth0 capture.pcapng

// be sure to change the client subnet below to match the local network

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"golang.org/x/sys/unix"
)

const (
	nanosPerSecond = int64(1_000_000_000)
	listenPort     = 27005
)

func ipInSubnet(ip net.IP, subnet net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return subnet.Contains(ip4)
}

func dataToHex(b []byte) string {
	return hex.EncodeToString(b)
}

func parsePacketRX(payload []byte, senderIP net.IP, senderPort int) {
	fmt.Printf("%s:%d - %s\n", senderIP.String(), senderPort, dataToHex(payload))
}

func mustIPv4Net(cidr string) net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("bad cidr %q: %v", cidr, err)
	}
	return *n
}

func setSockOptInt(fd int, level int, opt int, val int) error {
	return unix.SetsockoptInt(fd, level, opt, val)
}

func setMulticastIFByIndex(fd int, ifindex int) error {
	// Linux supports IP_MULTICAST_IF with struct ip_mreqn (imr_ifindex).
	// Use SetsockoptIpMreqn if available; otherwise fall back to IP_MULTICAST_IF as int.
	mreqn := &unix.IPMreqn{Ifindex: int32(ifindex)}
	return unix.SetsockoptIPMreqn(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_IF, mreqn)
}

func main() {
	var (
		ifaceName = flag.String("i", "", "interface to send packets through (name, e.g. eth0)")
		loopback  = flag.Bool("l", false, "enable multicast loopback")
		speed     = flag.Float64("s", 1.0, "replay speed relative to pcap timestamps")
		interval  = flag.Int("c", -1, "constant milliseconds between packets (-1 to use pcap timestamps)")
		repeat    = flag.Int("r", 1, "number of times to loop data (-1 for infinite loop)")
		ttl       = flag.Int("t", -1, "multicast ttl (-1 to leave default)")
		broadcast = flag.Bool("b", false, "enable broadcast (SO_BROADCAST)")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"udpreplaygo (Go rewrite)\nusage: %s [-i iface] [-l] [-s speed] [-c millisec] [-r repeat] [-t ttl] [-b] pcap\n\n",
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	pcapPath := flag.Arg(0)

	if *speed < 0 {
		log.Fatalf("speed must be positive")
	}
	if *interval != -1 && *interval < 0 {
		log.Fatalf("interval must be non-negative or -1")
	}
	if *repeat != -1 && *repeat <= 0 {
		log.Fatalf("repeat must be positive integer or -1")
	}
	if *ttl != -1 && *ttl < 0 {
		log.Fatalf("ttl must be non-negative integer or -1")
	}

	// Subnet 192.168.1.0/24
	clientSubnet := mustIPv4Net("192.168.1.0/24")

	// Create UDP socket (IPv4)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		log.Fatalf("socket: %v", err)
	}
	defer unix.Close(fd)

	// Bind to :27005
	var bindAddr unix.SockaddrInet4
	bindAddr.Port = listenPort
	// bindAddr.Addr = [4]byte{0,0,0,0} // INADDR_ANY by default zero
	if err := unix.Bind(fd, &bindAddr); err != nil {
		log.Fatalf("bind: %v", err)
	}

	// Options similar to the C++ code
	if *ifaceName != "" {
		ifi, err := net.InterfaceByName(*ifaceName)
		if err != nil {
			log.Fatalf("InterfaceByName(%q): %v", *ifaceName, err)
		}
		if err := setMulticastIFByIndex(fd, ifi.Index); err != nil {
			log.Fatalf("setsockopt(IP_MULTICAST_IF): %v", err)
		}
	}
	if *loopback {
		if err := setSockOptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP, 1); err != nil {
			log.Fatalf("setsockopt(IP_MULTICAST_LOOP): %v", err)
		}
	}
	if *broadcast {
		if err := setSockOptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
			log.Fatalf("setsockopt(SO_BROADCAST): %v", err)
		}
	}
	if *ttl != -1 {
		// This matches your code (multicast ttl). If you want unicast TTL too, add IP_TTL.
		if err := setSockOptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, *ttl); err != nil {
			log.Fatalf("setsockopt(IP_MULTICAST_TTL): %v", err)
		}
	}

	// Learn the sender by waiting for the first incoming UDP packet
	fmt.Println("Waiting for an incoming UDP packet...")
	buf := make([]byte, 1500)
	var sender unix.SockaddrInet4
	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			log.Fatalf("recvfrom: %v", err)
		}
		_ = n
		// Only accept IPv4 sender here (matches your sockaddr_in)
		switch sa := from.(type) {
		case *unix.SockaddrInet4:
			sender = *sa
			fmt.Printf("First packet received from IP: %d.%d.%d.%d, Port: %d\n",
				sender.Addr[0], sender.Addr[1], sender.Addr[2], sender.Addr[3], sender.Port,
			)
			goto HAVE_SENDER
		default:
			// ignore non-IPv4
		}
	}
HAVE_SENDER:

	senderIP := net.IPv4(sender.Addr[0], sender.Addr[1], sender.Addr[2], sender.Addr[3])
	senderPort := sender.Port

	// Replay loop
	loops := 0
	for *repeat == -1 || loops < *repeat {
		loops++

		f, err := os.Open(pcapPath)
		if err != nil {
			log.Fatalf("open pcap: %v", err)
		}

		r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			_ = f.Close()
			log.Fatalf("pcap read: %v", err)
		}

		var (
			startWall   time.Time // monotonic-bearing time.Now()
			pcapStart   time.Time
			deadline    time.Time
			haveStart   bool
			firstPacket = true
		)

		// Decoder: Ethernet -> (0..n VLAN tags) -> IPv4 -> UDP
		// We’ll just use NewPacket and pull layers; it handles stacked Dot1Q reasonably well.
		for {
			data, ci, err := r.ReadPacketData()
			if err != nil {
				break
			}
			if firstPacket {
				firstPacket = false
				pcapStart = ci.Timestamp
				startWall = time.Now()
				deadline = startWall
				haveStart = true
			}
			if !haveStart {
				continue
			}

			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

			ipLayer := pkt.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			ip4, _ := ipLayer.(*layers.IPv4)
			if ip4 == nil || ip4.Version != 4 || ip4.Protocol != layers.IPProtocolUDP {
				continue
			}

			udpLayer := pkt.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				continue
			}
			udp, _ := udpLayer.(*layers.UDP)
			if udp == nil {
				continue
			}
			payload := udp.Payload
			if len(payload) == 0 {
				continue
			}

			// If source IP is in 192.168.17.0/24, treat as “client packet” and block waiting for real client traffic.
			if ipInSubnet(ip4.SrcIP, clientSubnet) {
				// Wait for an incoming UDP packet (like your C++ recvfrom inside the loop)
				_, _, err := unix.Recvfrom(fd, buf, 0)
				if err != nil {
					_ = f.Close()
					log.Fatalf("recvfrom (client wait): %v", err)
				}
				continue
			}

			// Timing control
			if *interval != -1 {
				// constant milliseconds between packets
				deadline = deadline.Add(time.Duration(*interval) * time.Millisecond)
			} else {
				// deadline = startWall + (pcap_ts - pcapStart) * speed
				delta := ci.Timestamp.Sub(pcapStart)
				if *speed != 1.0 {
					delta = time.Duration(float64(delta) * (*speed))
				}
				deadline = startWall.Add(delta)
			}

			// sleep until deadline (absolute-ish)
			if d := time.Until(deadline); d > 0 {
				time.Sleep(d)
			}

                        // Print and send
                        parsePacketRX(payload, senderIP, senderPort)

                        var dst unix.SockaddrInet4
                        dst.Port = senderPort
                        copy(dst.Addr[:], sender.Addr[:])

                        if err := unix.Sendto(fd, payload, 0, &dst); err != nil {
                        	_ = f.Close()
                           	log.Fatalf("sendto: %v", err)
                        }
		}

		_ = f.Close()
	}

	// done
}

