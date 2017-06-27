package icmp

import (
	"log"
	"net"
	"os"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func Handler(message string, ip string) {

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("listen err, %s", err)
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte(message),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Println(err)
	}
	if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(ip)}); err != nil {
		log.Printf("WriteTo err, %s", err)
	}

}