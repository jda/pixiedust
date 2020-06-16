// pixiedust is a tool for extracting Ubiquiti UniFi configuration
// data from packet capture files.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
)

func init() {
	flag.Set("logtostderr", "true")
}

func main() {
	var wg sync.WaitGroup

	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	fname := flag.String("in", "", "input file name (pcap)")
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

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

	readStream(&wg, r)
	wg.Wait()
}

func readStream(wg *sync.WaitGroup, r *pcapgo.Reader) {

	// Set up assembly
	streamFactory := &httpStreamFactory{wg}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(r, layers.LayerTypeEthernet)
	packets := packetSource.Packets()
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}

			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		}
	}
}
