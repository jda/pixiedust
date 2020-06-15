// pixiedust is a tool for extracting Ubiquiti UniFi configuration
// data from packet capture files.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
)

func init() {
	flag.Set("logtostderr", "true")
}

func main() {
	fname := flag.CommandLine.String("in", "", "input file name (pcap)")
	flag.Parse()

	if *fname == "" {
		fmt.Println("error: no input file")
		os.Exit(1)
	}

	f, err := os.Open(*fname)
	if err != nil {
		fmt.Printf("error: cannot open input: %s\n", err)
		os.Exit(1)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Printf("error: cannot parse: %s\n", err)
		os.Exit(1)
	}

	/*
		need to extract http streams https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go
		default runmode: track/harvest secrets
		extra: pull config info
	*/

	defer util.Run()()

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(r, layers.LayerTypeEthernet)
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				// log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
