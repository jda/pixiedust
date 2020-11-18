// pixiedust is a tool for extracting Ubiquiti UniFi configuration
// data from packet capture files.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
	"sync"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
)

var quiet = false
var geo = false

func init() {
	flag.Set("logtostderr", "true")
}

func main() {
	var wg sync.WaitGroup

	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	fname := flag.String("in", "", "input file name (pcap)")
	keyFile := flag.String("keys", "", "file containing known keys")
	keyOut := flag.Bool("findkeys", false, "extracts keys from pcap (and suppress other output)")

	flag.Parse()

	if *keyOut {
		flag.Set("logtostderr", "false")
		quiet = true
	}

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			glog.Fatal(err)
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
		glog.Fatalf("cannot open input: %s", err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		glog.Fatalf("cannot parse: %s", err)
	}

	if *keyFile != "" {
		// load keys from file
		err = loadKeys(*keyFile)
		if err != nil {
			glog.Errorf("could not load keys from %s: %s", *keyFile, err)
		}
	}

	readStream(&wg, r)
	wg.Wait()

	if *keyOut {
		for _, v := range sk.v {
			fmt.Println(v)
		}
	}
}

func loadKeys(kf string) error {
	f, err := os.Open(kf)
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Split(bufio.ScanLines)
	for s.Scan() {
		sk.v = append(sk.v, s.Text())
	}

	return nil
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
