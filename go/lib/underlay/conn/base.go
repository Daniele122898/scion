// Copyright 2017 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build go1.9 && linux
// +build go1.9,linux

// Package conn implements underlay sockets.
package conn

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/log"
)

type connUDPBase struct {
	conn   *net.UDPConn
	Listen *net.UDPAddr
	Remote *net.UDPAddr
	rxOob  []byte
	txOob  []byte
	closed bool
}

func (c *connUDPBase) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	n, oobn, _, src, err := c.conn.ReadMsgUDP(b, c.rxOob)
	kTime := time.Now()
	if err != nil {
		return n, src, err
	}
	if oobn > 0 {
		var (
			scionLayer slayers.SCION
			hbhLayer   slayers.HopByHopExtn
		)
		if _, err2 := decodeLayers(b, &scionLayer, &hbhLayer); err2 == nil && hbhLayer.ExtLen == 7 {
			log.Info(fmt.Sprintf("============================================== READF PACKET"))
			// TODO (daniele): Check for the correct option type
			op := hbhLayer.Options[0]
			offsetData := hbhoffset(op.OptData)
			offsetHeader, id := offsetData.parseOffsetHeaderData()
			// TODO (daniele): Do we really want to use goTime as backup? It could ruin our offsets
			// TODO (daniele): Re-add after SW TS are fixed
			//kTime, err := parseOOB(c.rxOob[:oobn])
			//if err != nil {
			//	kTime = goTime // Use go time as backup
			//	log.Info("Used Go time as backup")
			//}
			log.Info("kernel timestamp readfrom: ", "nano", kTime.Nanosecond())
			//kTime = goTime

			var offset int64 = 0
			pathId := string(id)
			od, ok := tsDataMap[pathId]
			if ok && !od.prevIngTs.IsZero() {
				offset = kTime.Sub(od.prevIngTs).Nanoseconds()
				offset = normalize(offset)
			}
			tsDataMap.addOrUpdateIngressTime(kTime, pathId)

			// TODO (daniele): CHECK IF OFFSETS ARE SIMILAR
			checkOffsetConditions(offsetHeader, offset, pathId)

			delta := offsetHeader - offset
			log.Info("============= Reading Packet TS: \n",
				"id", pathId,
				"offset", offset,
				"headoff", offsetHeader,
				"delta", delta,
				"listen", c.Listen.String(),
				"remote", c.Remote.String())
		}
	}

	return n, src, err
	//return c.conn.ReadFromUDP(b)
}

func (c *connUDPBase) Write(b []byte) (int, error) {
	log.Info(" ========================= RANDOM WRITE CALL ============= ")
	return c.conn.Write(b)
}

func (c *connUDPBase) WriteTo(b []byte, dst *net.UDPAddr) (int, error) {
	var (
		scionLayer slayers.SCION
		hbhLayer   slayers.HopByHopExtn
		udpLayer   slayers.UDP
	)
	// TODO (daniele): Get rid of this decode layer call
	_, err := decodeLayers(b, &scionLayer, &hbhLayer, &udpLayer)
	// Ideally we'd have a SIG running that first receives a packet, then sends it out,
	// thus correctly storing previous timestamps. But in our test scenario, c.go directly
	// uses the dispatchers write function and never first reads. Thus technically
	// never reading and thus never creating prevIng Timestamps. For our PoC testing,
	// i'll hack in that we use our egress timestamps as prev and penultimate timestamps.
	isOrigin := hbhLayer.ExtLen == 0
	var pathId string
	if err == nil {
		if id, ok := ExtFingerprint(&scionLayer); ok {
			if scionLayer.PathType == scion.PathType && len(udpLayer.Payload) > 0 {
				//if data := string(udpLayer.Payload); data == "Hello, world!" {
				//if len(udpLayer.Payload) == 4 {
				pknr, _ := byteSliceToInt32(udpLayer.Payload)
				log.Info(fmt.Sprintf("============================================== WRITE PACKET %d", pknr))

				pathId = string(id)

				// Calculate offset
				var offset int64 = 0

				if od, ok := tsDataMap[pathId]; ok {
					log.Info("=========== Writer Data",
						"penult", od.penultIngTs.UnixNano(),
						"penult zero", od.penultIngTs.IsZero(),
						"last", od.prevIngTs.UnixNano(),
						"last zero", od.prevIngTs.IsZero(),
						"egre", od.prevEgrTs.UnixNano(),
						"egre zero", od.prevEgrTs.IsZero())
				}

				if od, ok := tsDataMap[pathId]; ok && !od.penultIngTs.IsZero() && !od.prevEgrTs.IsZero() {
					offset = od.prevEgrTs.Sub(od.penultIngTs).Nanoseconds()
					offset = normalize(offset)
				}
				// TODO (daniele): Remove this temporary measure
				getGoTxTimestamp(isOrigin, pathId)

				// Testing offset

				// 64bit offset -> 8 bytes
				// 20 byte pathID
				// -> 28 bytes
				// -> ext length of 7
				hbhData := make([]byte, 8, 28)
				int64ToByteSlice(offset, hbhData)
				hbhData = append(hbhData, id...)
				var optX = slayers.HopByHopOption{
					OptType:  0xFD, // Experimental testing
					OptData:  hbhData,
					OptAlign: [2]uint8{8, 2},
				}
				nhbh := &slayers.HopByHopExtn{}
				nhbh.NextHdr = common.L4UDP
				nhbh.Options = []*slayers.HopByHopOption{&optX}

				udpCutoff := len(b) - int(udpLayer.Length)
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{FixLengths: true}
				err := nhbh.SerializeTo(buf, opts)
				if err != nil {
					log.Info("Failed to serialize new hbh ext", "err", err)
				} else {
					udpBytes := make([]byte, udpLayer.Length)
					copy(udpBytes, b[udpCutoff:])
					restBytes := b[:udpCutoff]
					hbhBytes := buf.Bytes()
					nhbhBytes := len(buf.Bytes())
					// construct new byte slice
					b = append(restBytes, hbhBytes...)
					b = append(b, udpBytes...)
					// Fix Scion header values
					// Change next Header
					b[4] = byte(common.HopByHopClass)
					// Change payloadLen
					var paylen int16 = 0
					paylen |= int16(b[7])
					paylen |= int16(b[6]) << 8
					paylen += int16(nhbhBytes)
					b[6] = byte(paylen >> 8)
					b[7] = byte(paylen)
					log.Info("======== Writing packet: \n",
						"isOrigin", isOrigin,
						"id", pathId,
						"offset", offset,
						"listen", c.Listen.String(),
						"remote", c.Remote.String())
				}
			}
		}
	}

	var n int
	if c.Remote != nil {
		n, err = c.conn.Write(b)
	} else {
		n, err = c.conn.WriteTo(b, dst)
	}

	//if len(pathId) > 0 {
	//	_ = sockctrl.SockControl(c.conn, func(fd int) error {
	//		return readTxTimestamp(fd, c, isOrigin, pathId)
	//	})
	//}

	return n, err
	//return c.conn.WriteTo(b, dst)
}

func (c *connUDPBase) LocalAddr() *net.UDPAddr {
	return c.Listen
}

func (c *connUDPBase) RemoteAddr() *net.UDPAddr {
	return c.Remote
}

func (c *connUDPBase) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}
