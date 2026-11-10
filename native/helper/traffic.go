package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Traffic is the bytes the core's outbounds have carried, sent with each heartbeat so
// the application can show the speed. Mirrors desktop/core/traffic.go.
type Traffic struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

var statsClient = func() *http.Client {
	transport := &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Second, DisableCompression: true, Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: transport, Timeout: time.Second}
}()

// freeLoopbackPort is a loopback TCP port nothing listens on now.
func freeLoopbackPort() (int, error) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return port, listener.Close()
}

// coreTraffic asks the core's statistics service (gRPC QueryStats) on its loopback port.
func coreTraffic(ctx context.Context, port int) (Traffic, error) {
	pattern := "outbound>>>"
	message := append([]byte{0x0a, byte(len(pattern))}, pattern...)
	frame := binary.BigEndian.AppendUint32([]byte{0}, uint32(len(message)))
	frame = append(frame, message...)
	request, e := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1:"+itoa(port)+"/xray.app.stats.command.StatsService/QueryStats", bytes.NewReader(frame))
	if e != nil {
		return Traffic{}, e
	}
	request.Header.Set("content-type", "application/grpc")
	request.Header.Set("te", "trailers")
	response, e := statsClient.Do(request)
	if e != nil {
		return Traffic{}, e
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
	status := response.Trailer.Get("grpc-status")
	if status == "" {
		status = response.Header.Get("grpc-status")
	}
	if e != nil || len(body) > 256*1024 || response.StatusCode != 200 || status != "0" {
		return Traffic{}, failure("CONNECT_TIMEOUT")
	}
	return parseTraffic(body)
}

// parseTraffic reads a QueryStatsResponse frame: repeated Stat{name = 1, value = 2}
// named outbound>>>TAG>>>traffic>>>uplink|downlink. DNS answered inside the core and
// blocked connections are not counted.
func parseTraffic(body []byte) (Traffic, error) {
	invalid := failure("CONNECT_TIMEOUT")
	if len(body) < 5 || body[0] != 0 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
		return Traffic{}, invalid
	}
	stats, ok := protoFields(body[5:])
	if !ok {
		return Traffic{}, invalid
	}
	var traffic Traffic
	for _, field := range stats {
		if field.number != 1 || field.bytes == nil {
			continue
		}
		parts, ok := protoFields(field.bytes)
		if !ok {
			return Traffic{}, invalid
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
			traffic.Up += value
		case "downlink":
			traffic.Down += value
		}
	}
	return traffic, nil
}

type protoField struct {
	number int
	varint uint64
	bytes  []byte
}

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
