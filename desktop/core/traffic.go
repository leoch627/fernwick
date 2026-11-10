package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// TrafficSample is what the core has carried since it started, read at At.
type TrafficSample struct {
	Up, Down uint64
	At       time.Time
}

// TrafficRate is bytes per second.
type TrafficRate struct{ Up, Down uint64 }

// trafficReader is a network driver that can read the running core's byte counters.
type trafficReader interface {
	Traffic(ctx context.Context) (TrafficSample, bool)
}

// The core's statistics service (Xray StatsService) answers gRPC on a loopback port
// that only it serves; nothing else of the core's API is enabled.
func coreStatsConfig(port int) (api, stats, policy map[string]any) {
	return map[string]any{"tag": "api", "listen": "127.0.0.1:" + strconv.Itoa(port), "services": []string{"StatsService"}},
		map[string]any{},
		map[string]any{"system": map[string]any{"statsOutboundUplink": true, "statsOutboundDownlink": true}}
}

var statsClient = func() *http.Client {
	transport := &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Second, DisableCompression: true, Protocols: new(http.Protocols)}
	// gRPC without TLS: HTTP/2 from the first byte.
	transport.Protocols.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}()

const maxStatsReply = 256 * 1024

// CoreTraffic reads the bytes the core's outbounds have carried, up and down. DNS
// answered inside the core and blocked connections are not counted.
func CoreTraffic(ctx context.Context, port int) (TrafficSample, error) {
	if port < 1024 || port > 65535 {
		return TrafficSample{}, NewAppError("INVALID_INPUT")
	}
	// QueryStatsRequest{pattern: "outbound>>>"} in a gRPC frame.
	pattern := "outbound>>>"
	message := append([]byte{0x0a, byte(len(pattern))}, pattern...)
	frame := binary.BigEndian.AppendUint32([]byte{0}, uint32(len(message)))
	frame = append(frame, message...)
	request, err := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1:"+strconv.Itoa(port)+"/xray.app.stats.command.StatsService/QueryStats", bytes.NewReader(frame))
	if err != nil {
		return TrafficSample{}, err
	}
	request.Header.Set("content-type", "application/grpc")
	request.Header.Set("te", "trailers")
	response, err := statsClient.Do(request)
	if err != nil {
		return TrafficSample{}, NewAppError("CONNECT_TIMEOUT")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxStatsReply+1))
	status := response.Trailer.Get("grpc-status")
	if status == "" {
		status = response.Header.Get("grpc-status")
	}
	if err != nil || len(body) > maxStatsReply || response.StatusCode != 200 || status != "0" {
		return TrafficSample{}, NewAppError("CONNECT_TIMEOUT")
	}
	up, down, err := parseTrafficStats(body)
	if err != nil {
		return TrafficSample{}, err
	}
	return TrafficSample{Up: up, Down: down, At: time.Now()}, nil
}

// parseTrafficStats reads a QueryStatsResponse frame: repeated Stat{name = 1, value = 2}
// named outbound>>>TAG>>>traffic>>>uplink|downlink.
func parseTrafficStats(body []byte) (up, down uint64, err error) {
	invalid := NewAppError("CONNECT_TIMEOUT")
	if len(body) < 5 || body[0] != 0 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
		return 0, 0, invalid
	}
	stats, ok := protoFields(body[5:])
	if !ok {
		return 0, 0, invalid
	}
	for _, field := range stats {
		if field.number != 1 || field.bytes == nil {
			continue
		}
		parts, ok := protoFields(field.bytes)
		if !ok {
			return 0, 0, invalid
		}
		var name string
		var value uint64
		for _, part := range parts {
			switch {
			case part.number == 1 && part.bytes != nil:
				name = string(part.bytes)
			case part.number == 2 && part.bytes == nil:
				value = part.varint
			}
		}
		segments := strings.Split(name, ">>>")
		if len(segments) != 4 || segments[0] != "outbound" || segments[2] != "traffic" || segments[1] == "dns-out" || segments[1] == "block" || value > 1<<62 {
			continue
		}
		switch segments[3] {
		case "uplink":
			up += value
		case "downlink":
			down += value
		}
	}
	return up, down, nil
}

type protoField struct {
	number int
	varint uint64
	bytes  []byte
}

// protoFields splits a protobuf message into its fields: varints and length-delimited
// values are kept, fixed-width ones skipped.
func protoFields(data []byte) ([]protoField, bool) {
	fields := []protoField{}
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 || key>>3 == 0 || key>>3 > 1<<29 {
			return nil, false
		}
		data = data[n:]
		field := protoField{number: int(key >> 3)}
		switch key & 7 {
		case 0:
			value, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, false
			}
			field.varint, data = value, data[n:]
		case 1, 5:
			size := 8
			if key&7 == 5 {
				size = 4
			}
			if len(data) < size {
				return nil, false
			}
			data = data[size:]
			continue
		case 2:
			length, n := binary.Uvarint(data)
			if n <= 0 || length > uint64(len(data)-n) {
				return nil, false
			}
			field.bytes, data = data[n:n+int(length)], data[n+int(length):]
		default:
			return nil, false
		}
		fields = append(fields, field)
	}
	return fields, true
}

// TrafficMeter turns successive samples into a rate. A sample older than the last one
// or from a restarted core (counters went down) starts over.
type TrafficMeter struct {
	last TrafficSample
	rate TrafficRate
	have bool
}

func (m *TrafficMeter) Reset() { *m = TrafficMeter{} }
func (m *TrafficMeter) Add(sample TrafficSample) TrafficRate {
	if !m.have || sample.Up < m.last.Up || sample.Down < m.last.Down || sample.At.Before(m.last.At) {
		*m = TrafficMeter{last: sample, have: true}
		return m.rate
	}
	elapsed := sample.At.Sub(m.last.At)
	// The service reports with its heartbeat: a sample read twice changes nothing.
	if elapsed < 250*time.Millisecond {
		return m.rate
	}
	seconds := elapsed.Seconds()
	m.rate = TrafficRate{Up: uint64(float64(sample.Up-m.last.Up) / seconds), Down: uint64(float64(sample.Down-m.last.Down) / seconds)}
	m.last = sample
	return m.rate
}

// FormatRate shows a rate in at most three digits: "0 B/s", "9.6 KB/s", "128 MB/s".
func FormatRate(rate uint64) string {
	if rate < 1000 {
		return strconv.FormatUint(rate, 10) + " B/s"
	}
	value := float64(rate)
	for _, unit := range []string{"KB", "MB", "GB"} {
		value /= 1024
		if value < 999.5 || unit == "GB" {
			if value < 9.95 {
				return fmt.Sprintf("%.1f %s/s", value, unit)
			}
			return fmt.Sprintf("%.0f %s/s", value, unit)
		}
	}
	return ""
}

// RateLevel is how many of eight bars a rate lights: one per fourfold step from 1 KB/s
// to 16 MB/s.
func RateLevel(rate uint64) int {
	level := 0
	for threshold := uint64(1024); level < 8 && rate >= threshold; threshold *= 4 {
		level++
	}
	return level
}
