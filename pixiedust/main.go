// pixiedust is a tool for extracting Ubiquiti UniFi configuration
// data from packet capture files.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
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

func loadKeys(keyfname string) error {
	file, err := os.Open(keyfname)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sk.AddKey(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func main() {
	var wg sync.WaitGroup

	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	fname := flag.String("in", "", "input file name (pcap)")
	flag.BoolVar(&showHeader, "header", false, "show inform header")
	flag.BoolVar(&showMsg, "message", false, "show config message")
	flag.BoolVar(&showCoords, "locate", false, "geolocate devices")
	keyfname := flag.String("keys", "", "file of keys")
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

	if *keyfname != "" {
		err = loadKeys(*keyfname)
		if err != nil {
			glog.Errorf("could not read keys from %s: %s", *keyfname, err)
		}
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Printf("error: cannot parse: %s\n", err)
		os.Exit(1)
	}

	/*
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
