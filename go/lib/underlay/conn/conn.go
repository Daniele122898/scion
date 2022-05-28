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
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/sockctrl"
)

// Calculate the oobSize needed to hold our timestamp data
const sizeOfTimespec = int(unsafe.Sizeof(syscall.Timespec{}))

var oobSize = syscall.CmsgSpace(sizeOfTimespec)

type hbhoffset []byte

// Messages is a list of ipX.Messages. It is necessary to hide the type alias
// between ipv4.Message, ipv6.Message and socket.Message.
type Messages []ipv4.Message

// Conn describes the API for an underlay socket
type Conn interface {
	ReadFrom([]byte) (int, *net.UDPAddr, error)
	ReadBatch(Messages) (int, error)
	Write([]byte) (int, error)
	WriteTo([]byte, *net.UDPAddr) (int, error)
	WriteBatch(Messages, int) (int, error)
	LocalAddr() *net.UDPAddr
	RemoteAddr() *net.UDPAddr
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SetDeadline(time.Time) error
	Close() error
}

// Config customizes the behavior of an underlay socket.
type Config struct {
	// ReceiveBufferSize is the size of the operating system receive buffer, in
	// bytes.
	ReceiveBufferSize int
}

// New opens a new underlay socket on the specified addresses.
//
// The config can be used to customize socket behavior.
func New(listen, remote *net.UDPAddr, cfg *Config) (Conn, error) {
	a := listen
	if remote != nil {
		a = remote
	}
	if listen == nil && remote == nil {
		panic("either listen or remote must be set")
	}
	if a.IP.To4() != nil {
		return newConnUDPIPv4(listen, remote, cfg)
	}
	return newConnUDPIPv6(listen, remote, cfg)
}

type connUDPIPv4 struct {
	connUDPBase
	pconn *ipv4.PacketConn
}

func newConnUDPIPv4(listen, remote *net.UDPAddr, cfg *Config) (*connUDPIPv4, error) {
	cc := &connUDPIPv4{}
	if err := cc.initConnUDP("udp4", listen, remote, cfg); err != nil {
		return nil, err
	}
	cc.pconn = ipv4.NewPacketConn(cc.conn)
	return cc, nil
}

// TODO (daniele): Completely removed the ReadBatch call as it does NOT work for OOB data.
// https://github.com/golang/go/issues/32465
// ReadBatch reads up to len(msgs) packets, and stores them in msgs.
// It returns the number of packets read, and an error if any.
func (c *connUDPIPv4) ReadBatch(msgs Messages) (int, error) {
	n, oobn, _, src, err := c.conn.ReadMsgUDP(msgs[0].Buffers[0], c.txOob)
	if n == 0 || err != nil {
		return 0, err
	}

	msgs[0].N = n
	msgs[0].Addr = src

	goTime := time.Now()

	var (
		scionLayer slayers.SCION
		hbhLayer   slayers.HopByHopExtn
	)

	if _, err2 := decodeLayers(msgs[0].Buffers[0], &scionLayer, &hbhLayer); err2 == nil && hbhLayer.ExtLen == 7 {

		kTime, err2 := parseOOB(c.txOob[:oobn])
		if err2 != nil {
			kTime = goTime // Use go time as backup
			log.Info("Used Go time as backup")
		}
		op := hbhLayer.Options[0]
		offsetData := hbhoffset(op.OptData)
		offsetHeader, id := offsetData.parseOffsetHeaderData()
		pathId := string(id)

		var offset int64 = 0
		if od, ok := offsets[pathId]; ok && !od.prevIngTs.IsZero() {
			offset = kTime.Sub(od.prevIngTs).Nanoseconds()
		}

		// TODO (daniele): CHECK IF OFFSETS ARE SIMILAR

		offsets.addOrUpdateIngressTime(kTime, pathId)

		log.Info("======== Reading Batch TS: \n",
			"id", pathId,
			"offset", offset,
			"headoff", offsetHeader,
			"delta", abs(offsetHeader-offset),
			"listen", c.Listen.String(),
			"remote", c.Remote.String())
	}

	return 1, err
}

func (c *connUDPIPv4) WriteBatch(msgs Messages, flags int) (int, error) {

	var pathId string
	for i, _ := range msgs {
		var (
			scionLayer slayers.SCION
			hbhLayer   slayers.HopByHopExtn
		)

		if _, err2 := decodeLayers(msgs[i].Buffers[0], &scionLayer, &hbhLayer); err2 != nil || hbhLayer.ExtLen != 7 {
			continue
		}
		// TODO (daniele): Check for the correct option type
		op := hbhLayer.Options[0]
		offsetData := hbhoffset(op.OptData)
		offsetHeader, id := offsetData.parseOffsetHeaderData()
		pathId = string(id)

		// Calculate offset
		var offset int64 = 0

		if od, ok := offsets[pathId]; ok {
			log.Info("=========== Writer BATCH Data",
				"penult", od.penultIngTs.UnixNano(),
				"last", od.prevIngTs.UnixNano(),
				"egre", od.prevEgrTs.UnixNano())
		}

		if od, ok := offsets[pathId]; ok && !od.penultIngTs.IsZero() && !od.prevEgrTs.IsZero() {
			offset = od.prevEgrTs.Sub(od.penultIngTs).Nanoseconds()
		}
		log.Info("======== Write Batch TS: \n",
			"id", pathId,
			"offset", offset,
			"headoff", offsetHeader,
			"delta", abs(offsetHeader-offset),
		)

		// TODO (daniele): Check against header offset for anomalities

		// Write our own offset data into it
		buf := msgs[i].Buffers[0]
		dumpByteSlice(buf)
		actScionHdrLen := scionLayer.HdrLen * 4
		dataStart := actScionHdrLen + 4
		offsetslice := buf[dataStart : dataStart+8]
		int64ToByteSlice(offset, offsetslice)
		buf[len(buf)-1] = buf[len(buf)-1] + 1
		dumpByteSlice(buf)

	}
	n, err := c.pconn.WriteBatch(msgs, flags)

	if len(pathId) > 0 {
		_ = sockctrl.SockControl(c.conn, func(fd int) error {
			return readTxTimestamp(fd, &c.connUDPBase, false, pathId)
		})
	}

	return n, err

	//	// TODO (daniele): Rewrote Batch as loop of singles since the Batch calls dont work
	//	// with our OOB
	//	//log.Info("============ REACHED WRITE BATCH ================")

	//	//log.Info("============ LEAVING WRITE BATCH ================")
	//
	//	return len(msgs), nil
	//} else {
	//	return c.pconn.WriteBatch(msgs, flags)
	//}

}

// SetReadDeadline sets the read deadline associated with the endpoint.
func (c *connUDPIPv4) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

func (c *connUDPIPv4) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *connUDPIPv4) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

type connUDPIPv6 struct {
	connUDPBase
	pconn *ipv6.PacketConn
}

func newConnUDPIPv6(listen, remote *net.UDPAddr, cfg *Config) (*connUDPIPv6, error) {
	cc := &connUDPIPv6{}
	if err := cc.initConnUDP("udp6", listen, remote, cfg); err != nil {
		return nil, err
	}
	cc.pconn = ipv6.NewPacketConn(cc.conn)
	return cc, nil
}

// ReadBatch reads up to len(msgs) packets, and stores them in msgs.
// It returns the number of packets read, and an error if any.
func (c *connUDPIPv6) ReadBatch(msgs Messages) (int, error) {
	n, err := c.pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
	return n, err
}

func (c *connUDPIPv6) WriteBatch(msgs Messages, flags int) (int, error) {
	return c.pconn.WriteBatch(msgs, flags)
}

// SetReadDeadline sets the read deadline associated with the endpoint.
func (c *connUDPIPv6) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

func (c *connUDPIPv6) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *connUDPIPv6) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

type pathOffsetData struct {
	penultIngTs time.Time
	prevIngTs   time.Time
	prevEgrTs   time.Time
	counter     uint8
}

type offsetMap map[string]*pathOffsetData

var offsets offsetMap = make(map[string]*pathOffsetData)

type connUDPBase struct {
	conn   *net.UDPConn
	Listen *net.UDPAddr
	Remote *net.UDPAddr
	rxOob  []byte
	txOob  []byte
	closed bool
}

func (cc *connUDPBase) initConnUDP(network string, laddr, raddr *net.UDPAddr, cfg *Config) error {
	var c *net.UDPConn
	var err error
	if laddr == nil {
		return serrors.New("listen address must be specified")
	}
	if raddr == nil {
		if c, err = net.ListenUDP(network, laddr); err != nil {
			return serrors.WrapStr("Error listening on socket", err,
				"network", network, "listen", laddr)
		}
	} else {
		if c, err = net.DialUDP(network, laddr, raddr); err != nil {
			return serrors.WrapStr("Error setting up connection", err,
				"network", network, "listen", laddr, "remote", raddr)
		}
	}

	// TODO (daniele): Check differences in unix flags and syscall flags.
	tsflags := unix.SOF_TIMESTAMPING_SOFTWARE | unix.SOF_TIMESTAMPING_RX_SOFTWARE | // sw rx
		unix.SOF_TIMESTAMPING_TX_SOFTWARE | // sw tx
		unix.SOF_TIMESTAMPING_OPT_PKTINFO | unix.SOF_TIMESTAMPING_OPT_CMSG // for tx
	// TODO (daniele): Check difference to SO_TIMESTAMPNS and if this timestamp is really less accurate
	// Sadly SO_TIMESTAMPNS did not return any timestamps for TX.
	// Enable receiving of socket timestamps in ns.
	if err := sockctrl.SetsockoptInt(c, syscall.SOL_SOCKET, unix.SO_TIMESTAMPING_NEW, tsflags); err != nil {
		return serrors.WrapStr("Error setting SO_TIMESTAMPNS socket option", err,
			"listen", laddr, "remote", raddr)
	}

	// Set and confirm receive buffer size
	before, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return serrors.WrapStr("Error getting SO_RCVBUF socket option (before)", err,
			"listen", laddr, "remote", raddr)
	}
	target := cfg.ReceiveBufferSize
	if err = c.SetReadBuffer(target); err != nil {
		return serrors.WrapStr("Error setting recv buffer size", err,
			"listen", laddr, "remote", raddr)
	}
	after, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return serrors.WrapStr("Error getting SO_RCVBUF socket option (after)", err,
			"listen", laddr, "remote", raddr)
	}
	if after/2 < target {
		// Note: kernel doubles value passed in SetReadBuffer, value returned is the doubled value
		log.Info("Receive buffer size smaller than requested",
			"expected", target, "actual", after/2, "before", before/2)
	}
	cc.rxOob = make([]byte, oobSize)
	cc.txOob = make([]byte, oobSize)

	cc.conn = c
	cc.Listen = laddr
	cc.Remote = raddr
	return nil
}

// TODO (daniele): Potentially put into functions because of multithreading

func (c *connUDPBase) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	n, oobn, _, src, err := c.conn.ReadMsgUDP(b, c.rxOob)
	if err != nil {
		return n, src, err
	}
	if oobn > 0 {
		var (
			scionLayer slayers.SCION
			hbhLayer   slayers.HopByHopExtn
		)
		if _, err2 := decodeLayers(b, &scionLayer, &hbhLayer); err2 == nil && hbhLayer.ExtLen == 7 {

			// TODO (daniele): Check for the correct option type
			op := hbhLayer.Options[0]
			offsetData := hbhoffset(op.OptData)
			offsetHeader, id := offsetData.parseOffsetHeaderData()
			// TODO (daniele): Do we really want to use goTime as backup? It could ruin our offsets
			goTime := time.Now()
			kTime, err := parseOOB(c.rxOob[:oobn])
			if err != nil {
				kTime = goTime // Use go time as backup
				log.Info("Used Go time as backup")
			}

			var offset int64 = 0
			pathId := string(id)
			if od, ok := offsets[pathId]; ok && !od.prevIngTs.IsZero() {
				offset = kTime.Sub(od.prevIngTs).Nanoseconds()
			}

			// TODO (daniele): CHECK IF OFFSETS ARE SIMILAR

			offsets.addOrUpdateIngressTime(kTime, pathId)

			log.Info("============= Reading Packet TS: \n",
				"id", pathId,
				"offset", offset,
				"headoff", offsetHeader,
				"delta", abs(offsetHeader-offset),
				"listen", c.Listen.String(),
				"remote", c.Remote.String())
		}
	}

	return n, src, err
	//return c.conn.ReadFromUDP(b)
}

// Go only has builtin abs function for float64 :)
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
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
	isOrigin := hbhLayer.ExtLen > 0
	var idstr string
	if err == nil {
		if id, ok := ExtFingerprint(&scionLayer); ok {
			if data := string(udpLayer.Payload); data == "Hello, world!" {

				idstr = string(id)

				// Calculate offset
				var offset int64 = 0

				if od, ok := offsets[idstr]; ok {
					log.Info("=========== Writer Data",
						"penult", od.penultIngTs.UnixNano(),
						"last", od.prevIngTs.UnixNano(),
						"egre", od.prevEgrTs.UnixNano())
				}

				if od, ok := offsets[idstr]; ok && !od.penultIngTs.IsZero() && !od.prevEgrTs.IsZero() {
					offset = od.prevEgrTs.Sub(od.penultIngTs).Nanoseconds()
				}

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
					udpBytes[len(udpBytes)-1] = udpBytes[len(udpBytes)-1] + 1
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
						"id", idstr,
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

	if len(idstr) > 0 {
		_ = sockctrl.SockControl(c.conn, func(fd int) error {
			return readTxTimestamp(fd, c, isOrigin, idstr)
		})
	}

	return n, err
	//return c.conn.WriteTo(b, dst)
}

func int64ToByteSlice(n int64, b []byte) {
	for i := 0; i < 8; i++ {
		b[7-i] = byte(n >> (8 * i))
	}
}

func writeFields(w io.Writer, fields ...interface{}) bool {
	for _, f := range fields {
		if err := binary.Write(w, binary.LittleEndian, f); err != nil {
			return false
		}
	}
	return true
}

// Uniquely identifies the path based on the sequence of ASes and BRs and additionally
// the source and destination addresses. This should uniquely identify a complete path
// from SIG to SIG
func ExtFingerprint(scionLayer *slayers.SCION) ([]byte, bool) {
	path, ok := scionLayer.Path.(*scion.Raw)
	if !ok {
		return nil, false
	}
	h := sha1.New()
	for i := 0; i < path.NumHops; i++ {
		hf, err := path.GetHopField(i)
		if err != nil {
			return nil, false
		}
		if !writeFields(h, hf.ConsEgress, hf.ConsIngress) {
			return nil, false
		}
	}
	if !writeFields(h, scionLayer.RawSrcAddr, scionLayer.RawDstAddr, scionLayer.SrcIA, scionLayer.DstIA) {
		return nil, false
	}
	return h.Sum(nil), true
}

func dumpByteSlice(b []byte) {
	var a [4]byte
	n := (len(b) + 3) &^ 3
	for i := 0; i < n; i++ {
		if i%4 == 0 {
			fmt.Printf("%4d", i)
		}
		if i < len(b) {
			fmt.Printf(" %02X", b[i])
		} else {
			fmt.Print("   ")
		}
		if i >= len(b) {
			a[i%4] = ' '
		} else if b[i] < 32 || b[i] > 126 {
			a[i%4] = '.'
		} else {
			a[i%4] = b[i]
		}
		if i%4 == 3 {
			fmt.Printf("  %s\n", string(a[:]))
		}
	}
}

// We absolutely dont care about the actual data so we dont mind it being weirdly overwritten
var txbuff = make([]byte, 1<<16)

func readTxTimestamp(fd int, c *connUDPBase, isOrigin bool, pathId string) error {
	const timeout = 1 //ms
	const maxTries = 3

	for i := 0; i < maxTries; i++ {
		// wait for control message on error queue
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLPRI, Revents: 0}}
		if _, err := unix.Poll(fds, timeout); err != nil {
			log.Info("Failed to poll for control msg", "err", err)
			continue
		}

		// receive message
		_, oobn, _, _, err := unix.Recvmsg(fd, txbuff, c.txOob, unix.MSG_ERRQUEUE)
		if err != nil {
			log.Info("Couldn't find error msg", "err", err)
			continue
		}

		// TODO (daniele): Potentially use goTime as backup
		kTime, err := parseOOB(c.txOob[:oobn])
		if err != nil {
			log.Info("Couldn't parse OOB data", "err", err)
			continue
		}

		offsets.addOrUpdateEgressTime(kTime, pathId)
		// Very ugly hack to fix the current PoC SIG not having any ingress packets
		if isOrigin {
			offsets.addOrUpdateIngressTimeOrigin(kTime, pathId)
		}
		return nil
	}
	return nil
}

func parseOOB(oob []byte) (time.Time, error) {
	if len(oob) == 0 {
		return time.Time{}, serrors.New("Cant parse OOB as len is 0")
	}

	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return time.Time{}, err
	}

	var kTime time.Time
	for _, msg := range msgs {
		if msg.Header.Level != unix.SOL_SOCKET ||
			(msg.Header.Type != unix.SO_TIMESTAMPING && msg.Header.Type != unix.SO_TIMESTAMPING_NEW) {
			continue
		}
		ts, err := scmDataToTime(msg.Data)
		if err != nil {
			return time.Time{}, err
		}
		if ts.UnixNano() != 0 {
			kTime = ts
		}
	}

	return kTime, nil
}

// 2x64bit ints
var size = 16

//parses timestamps from socket control message
func scmDataToTime(data []byte) (kts time.Time, err error) {
	// kernel
	kts, err = byteToTime(data[:size])
	if err != nil {
		return time.Time{}, err
	}

	return kts, nil
}

// byteToTime converts LittleEndian bytes into a timestamp
func byteToTime(data []byte) (time.Time, error) {
	ts := &unix.Timespec{}
	b := bytes.NewReader(data)
	if err := binary.Read(b, binary.LittleEndian, ts); err != nil {
		return time.Time{}, err
	}
	return time.Unix(ts.Unix()), nil

}

// decodeLayers implements roughly the functionality of
// gopacket.DecodingLayerParser, but customized to our use case with a "base"
// layer and additional, optional layers in the given order.
// Returns the last decoded layer.
func decodeLayers(data []byte, base gopacket.DecodingLayer,
	opts ...gopacket.DecodingLayer) (gopacket.DecodingLayer, error) {

	if err := base.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	last := base
	for _, opt := range opts {
		if opt.CanDecode().Contains(last.NextLayerType()) {
			data := last.LayerPayload()
			if err := opt.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				return nil, err
			}
			last = opt
		}
	}
	return last, nil
}

func (m offsetMap) addOrUpdateEgressTime(ts time.Time, key string) {
	if od, ok := m[key]; ok {
		od.prevEgrTs = ts
	} else {
		m[key] = &pathOffsetData{
			prevEgrTs:   ts,
			penultIngTs: time.Time{},
			prevIngTs:   time.Time{},
			counter:     0,
		}
	}
}

func (m offsetMap) addOrUpdateIngressTime(ts time.Time, key string) {
	if od, ok := m[key]; ok {
		od.penultIngTs = od.prevIngTs
		od.prevIngTs = ts
	} else {
		m[key] = &pathOffsetData{
			prevIngTs:   ts,
			counter:     0,
			prevEgrTs:   time.Time{},
			penultIngTs: time.Time{},
		}
	}
}

func (m offsetMap) addOrUpdateIngressTimeOrigin(ts time.Time, key string) {
	if od, ok := m[key]; ok {
		od.penultIngTs = ts
		od.prevIngTs = ts
	} else {
		m[key] = &pathOffsetData{
			prevIngTs:   ts,
			penultIngTs: ts,
			prevEgrTs:   time.Time{},
			counter:     0,
		}
	}
}

func byteSliceToInt64(b []byte) (int64, bool) {
	if len(b) < 8 {
		return 0, false
	}

	var val int64 = 0
	for i := 0; i < 8; i++ {
		val |= int64(b[7-i]) << (8 * i)
	}
	return val, true
}

func (data hbhoffset) parseOffsetHeaderData() (offset int64, id []byte) {
	id = data[8:]
	// parse int
	offset, _ = byteSliceToInt64(data[:8])
	return offset, id
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

// NewReadMessages allocates memory for reading IPv4 Linux network stack
// messages.
func NewReadMessages(n int) Messages {
	m := make(Messages, n)
	for i := range m {
		// Allocate a single-element, to avoid allocations when setting the buffer.
		m[i].Buffers = make([][]byte, 1)
		// Allocate oob size
		//m[i].OOB = make([]byte, oobSize)
	}
	return m
}
