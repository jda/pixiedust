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

func init() {
	flag.Set("logtostderr", "true")
}

var showHeader bool
var showMsg bool
var showCoords bool
var showKeys bool

func main() {
	var wg sync.WaitGroup

	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	fname := flag.String("in", "", "input file name (pcap)")
	flag.BoolVar(&showHeader, "header", false, "show inform header")
	flag.BoolVar(&showMsg, "message", true, "show config message")
	flag.BoolVar(&showCoords, "locate", false, "geolocate devices")
	flag.BoolVar(&showKeys, "findkeys", false, "show keys")
	keyfname := flag.String("keys", "", "read keys from file")
	flag.Parse()

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

	if *keyfname != "" {
		err = loadKeys(*keyfname)
		if err != nil {
			glog.Errorf("could not read keys from %s: %s", *keyfname, err)
		}
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		glog.Fatalf("cannot parse: %s", err)
	}

	readStream(&wg, r)
	wg.Wait()

	if showKeys {
		for _, v := range sk.v {
			fmt.Println(v)
		}
	}
}

func loadKeys(keyfname string) error {
	f, err := os.Open(keyfname)
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Split(bufio.ScanLines)
	for s.Scan() {
		sk.v = append(sk.v, s.Text())
	}
	if err := s.Err(); err != nil {
		return err
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
