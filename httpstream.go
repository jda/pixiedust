package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"

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
	buf := bufio.NewReader(&h.r)

	src := h.net.Src().String()
	dest := h.net.Dst().String()

	for {
		hint, err := buf.Peek(4)
		if err == io.EOF {
			break
		} else if err != nil {
			slog.Error("could not read packet", "source", src, "destination", dest, "err", err)
			os.Exit(1)
		}

		if bytes.Equal(hint, []byte("POST")) {
			req, err := http.ReadRequest(buf)
			if err != nil {
				slog.Warn("could not read HTTP request", "source", src, "destination", dest, "err", err)
				continue
			}

			decodeRequest(req, src, dest)
			req.Body.Close()
			continue
		}

		if bytes.Equal(hint, []byte("HTTP")) {
			res, err := http.ReadResponse(buf, nil)
			if err != nil {
				slog.Warn("could not read HTTP response", "source", src, "destination", dest, "err", err)
				continue
			}

			decodeResponse(res, src, dest)
			res.Body.Close()
			continue
		}

		buf.Discard(4) // hint failed, so skip forward
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

	ctype := r.Header.Get("Content-type")
	if r.StatusCode == http.StatusOK && ctype == inform.InformContentType {
		handleInform(r.Body, src, dest)
		return
	}

	slog.Warn("unhandled HTTP response", "status_code", r.StatusCode, "content_type", ctype, "source", src, "destination", dest)

}

func decodeRequest(r *http.Request, src string, dest string) {
	if r.Method != http.MethodPost {
		return
	}

	if ctype := r.Header.Get("Content-type"); ctype != inform.InformContentType {
		slog.Info("unexpected HTTP request content type", "source", src, "destination", dest, "content_type", ctype)
		return
	}

	handleInform(r.Body, src, dest)
}

func handleInform(body io.ReadCloser, src string, dest string) {
	imsg, err := inform.DecodeHeader(body)
	if err != nil {
		slog.Warn("could not parse inform header", "source", src, "destination", dest, "err", err)
		return
	}

	if showHeader {
		fmt.Printf("%s->%s: %+v\n", src, dest, imsg)
	}

	payload, err := tryDecodePayload(imsg, body)
	if err != nil {
		slog.Warn("could not decrypt inform payload", "source", src, "destination", dest, "err", err)
		return
	}
	if showMsg {
		fmt.Printf("%s\n", payload)
	}
	extractInfo(payload, dest) // dest because keys come in responses
}

func tryDecodePayload(imsg inform.Header, eb io.ReadCloser) (clearBody []byte, err error) {
	ct, _ := io.ReadAll(eb)

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
