package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"googlemaps.github.io/maps"
)

type informMsg struct {
	Type       string `json:"_type"`
	MgmtCfg    string `json:"mgmt_cfg"`
	AuthKey    string
	RadioTable []Radio `json:"radio_table"`
	Location   Geo
	Serial     string `json:"serial"`
}

type Geo struct {
}

type Radio struct {
	ScanTable []Neighbor `json:"scan_table"`
}

type Neighbor struct {
	Band      string `json:"band"`
	BSSID     string `json:"bssid"`
	Bandwidth int    `json:"bw"`
	Channel   int    `json:"channel"`
	ESSID     string `json:"essid"`
	Noise     int    `json:"noise"`
	Signal    int    `json:"signal"`
	Age       int    `json:"age"`
}

var located SafeUniqueList

func extractInfo(payload []byte, src string) {
	var im informMsg
	payload = []byte(strings.ReplaceAll(string(payload), "\\n", ","))
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
				slog.Info("discovered key", "auth_key", im.AuthKey, "device", src)
				break
			}
		}
	}

	if showCoords == true && im.RadioTable != nil {
		updateGeo(im)
	}
}

func updateGeo(im informMsg) {
	// check if we've already dumped geo info for device

	if located.Exists(im.Serial) {
		return
	}

	pdKey := os.Getenv("PD_MAPS_API_KEY")
	if pdKey == "" {
		slog.Info("geolocation disabled because no API key is configured", "environment_variable", "PD_MAPS_API_KEY")
		return
	}

	neighbors := flattenNeighbors(im.RadioTable)
	waps := neighborsToWAP(neighbors)
	gRec := maps.GeolocationRequest{
		ConsiderIP:       false,
		WiFiAccessPoints: waps,
	}

	mc, err := maps.NewClient(maps.WithAPIKey(pdKey))
	if err != nil {
		slog.Error("could not initialize Google Maps client", "err", err)
		return
	}

	gr, err := mc.Geolocate(context.Background(), &gRec)
	if err != nil {
		slog.Error("could not geolocate device", "serial", im.Serial, "err", err)
		return
	}

	fmt.Printf("Device %s at %f,%f (%f)\n", im.Serial, gr.Location.Lat, gr.Location.Lng, gr.Accuracy)

	return
}

func neighborsToWAP(neighbors []Neighbor) []maps.WiFiAccessPoint {
	waps := []maps.WiFiAccessPoint{}

	for _, n := range neighbors {
		if n.Signal == 0 {
			continue
		}

		snr := n.Signal - n.Noise
		wap := maps.WiFiAccessPoint{
			MACAddress:         n.BSSID,
			SignalStrength:     float64(n.Signal),
			Channel:            n.Channel,
			SignalToNoiseRatio: float64(snr),
		}
		waps = append(waps, wap)
	}

	return waps
}

func flattenNeighbors(radios []Radio) []Neighbor {
	neighbors := []Neighbor{}

	for _, radio := range radios {
		neighbors = append(neighbors, radio.ScanTable...)
	}

	return neighbors
}
