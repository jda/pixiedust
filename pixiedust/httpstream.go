package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/jda/nanofi/inform"
)

type informMsg struct {
	Type    string `json:"_type"`
	MgmtCfg string `json:"mgmt_cfg"`
	AuthKey string
}

// SafeKeys is safe to use concurrently.
type SafeKeys struct {
	v   []string
	mux sync.RWMutex
}

// Keys returns list of keys
func (sk *SafeKeys) Keys() []string {
	sk.mux.RLock()
	defer sk.mux.RUnlock()
	return sk.v
}

// AddKey adds a unique key to sk
func (sk *SafeKeys) AddKey(key string) {
	sk.mux.Lock()
	defer sk.mux.Unlock()

	for _, k := range sk.v {
		if key == k { // bail if key already exists
			return
		}
	}

	sk.v = append(sk.v, key)
}

var sk SafeKeys

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	// read entire flow
	data, err := ioutil.ReadAll(&h.r)
	if err != nil {
		glog.Fatalf("failed to read entire stream: %s", err)
		return
	}
	buf := bufio.NewReader(bytes.NewReader(data))

	src := h.net.Src().String()
	dest := h.net.Dst().String()

	// try to read request
	req, err := http.ReadRequest(buf)
	if err == nil {
		decodeRequest(req, src, dest)
		req.Body.Close()
		return
	}

	// or response
	buf.Reset(bytes.NewReader(data))
	res, err := http.ReadResponse(buf, nil)
	if err == nil {
		decodeResponse(res, src, dest)
		res.Body.Close()
		return
	}
}

func decodeResponse(r *http.Response, src string, dest string) {
	if r.StatusCode == http.StatusNotFound {
		//glog.Infof("device %s not known to %s (or latter is not a controller)\n", dest, src)
		return
	}

	if r.StatusCode == http.StatusContinue {
		// whatever
		return
	}

	if r.StatusCode == http.StatusOK && r.Header.Get("Content-type") == inform.InformContentType {
		handleInform(r.Body, src, dest)
		return
	}

	glog.Warningf("unhandled code %d from %s\n", r.StatusCode, dest)

}

func decodeRequest(r *http.Request, src string, dest string) {
	if r.Method != http.MethodPost {
		return
	}

	if r.Header.Get("Content-type") != inform.InformContentType {
		return
	}

	handleInform(r.Body, src, dest)
}

func handleInform(body io.ReadCloser, src string, dest string) {
	imsg, err := inform.DecodeHeader(body)
	if err != nil {
		glog.Warningf("%s: could not parse inform header: %s", src, err)
		return
	}

	payload, err := tryDecodePayload(imsg, body)
	if err != nil {
		glog.Infof("%s->%s: could not decrypt inform payload", src, dest)
		return
	}
	extractInfo(payload, dest) // dest because keys come in responses
	// unmarshal here and harvest keys
	//glog.Infof("%s->%s\n%s\n\n", src, dest, payload)

}

func tryDecodePayload(imsg inform.Header, eb io.ReadCloser) (clearBody []byte, err error) {
	ct, _ := ioutil.ReadAll(eb)

	payload, err := imsg.DecodePayload(bytes.NewReader(ct), "")
	if err == nil {
		return payload, nil
	}

	keys := sk.Keys()
	for _, k := range keys {
		payload, err := imsg.DecodePayload(bytes.NewReader(ct), k)
		if err == nil {
			return payload, nil
		}
	}

	return nil, err
}

func extractInfo(payload []byte, src string) {
	var im informMsg
	payload = []byte(strings.ReplaceAll(string(payload), "\\n", ","))
	fmt.Printf("%s\n\n", payload)
	json.Unmarshal(payload, &im)

	if im.Type == "setparam" {
		chunks := strings.Split(im.MgmtCfg, ",")
		for _, c := range chunks {
			parts := strings.Split(c, "=")
			if len(parts) != 2 {
				continue
			}

			if parts[0] == "authkey" {
				im.AuthKey = parts[1]
				sk.AddKey(im.AuthKey)
				fmt.Printf("discovered key: %s for %s\n", im.AuthKey, src)
				break
			}
		}
	}

	// harvest location from APs

}
