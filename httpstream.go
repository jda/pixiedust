package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/jda/nanofi/inform"
)

// SafeUniqueList is safe to use concurrently.
type SafeUniqueList struct {
	v   []string
	mux sync.RWMutex
}

// Keys returns list of keys
func (sk *SafeUniqueList) Keys() []string {
	sk.mux.RLock()
	defer sk.mux.RUnlock()
	return sk.v
}

// AddKey adds a unique key to sk
func (sk *SafeUniqueList) AddKey(key string) {
	sk.mux.Lock()
	defer sk.mux.Unlock()

	for _, k := range sk.v {
		if key == k { // bail if key already exists
			return
		}
	}

	sk.v = append(sk.v, key)
}

// Exists returns true if key exists in list
func (sk *SafeUniqueList) Exists(key string) bool {
	sk.mux.RLock()
	defer sk.mux.RUnlock()

	for _, k := range sk.v {
		if key == k {
			return true
		}
	}

	return false
}

var sk SafeUniqueList

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	wg *sync.WaitGroup
}

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
	go hstream.run(h.wg) // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run(wg *sync.WaitGroup) {
	// read entire flow
	data, err := ioutil.ReadAll(&h.r)
	if err != nil {
		glog.Errorf("failed to read entire stream: %s", err)
		return
	}
	h.r.Close()

	buf := bufio.NewReader(bytes.NewReader(data))

	src := h.net.Src().String()
	dest := h.net.Dst().String()

	wg.Add(1)
	defer wg.Done()

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

	if showHeader {
		fmt.Printf("%s->%s: %+v\n", src, dest, imsg)
	}

	payload, err := tryDecodePayload(imsg, body)
	if err != nil {
		glog.Warningf("%s->%s: could not decrypt inform payload: %s", src, dest, err)
		//glog.Infof("%s->%s: could not decrypt inform payload %s\nheader: %+v", src, dest, err, imsg)
		return
	}
	if showMsg {
		fmt.Printf("%s\n", payload)
	}
	extractInfo(payload, dest) // dest because keys come in responses
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

	if err != nil {
		glog.Infof("failed to decrypt payload with known keys:\nheader: %+v\n payload: %+v", imsg, ct)
	}

	return nil, err
}
