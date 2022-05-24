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
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/lib/slayers"
	"golang.org/x/sys/unix"
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

// 64 is the current batch count being used in the dataplane.
var timestamps = make([]time.Time, 64)

// ReadBatch reads up to len(msgs) packets, and stores them in msgs.
// It returns the number of packets read, and an error if any.
func (c *connUDPIPv4) ReadBatch(msgs Messages) (int, error) {
	// TODO (daniele): Figure out how we can allocate OOB size without breaking everything...
	//for _, msg := range msgs {
	//	msg.OOB = make([]byte, oobSize)
	//}
	n, err := c.pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
	currTs := time.Now()
	nts, err := handleOOBBatch(msgs, timestamps)
	//TODO (daniele): Remove this entire loop, just for debug
	for i := 0; i < nts; i++ {
		timeDelay := currTs.Sub(timestamps[i])
		log.Info("OOB TS: ", "go ts", currTs.UnixNano(), "kernel ts", timestamps[i].UnixNano(), "difference", timeDelay.Nanoseconds())
	}
	return n, err
}

func (c *connUDPIPv4) WriteBatch(msgs Messages, flags int) (int, error) {
	return c.pconn.WriteBatch(msgs, flags)
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

type connUDPBase struct {
	conn      *net.UDPConn
	Listen    *net.UDPAddr
	Remote    *net.UDPAddr
	rxOob     []byte
	txOob     []byte
	prevIngTs time.Time
	closed    bool
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

var (
	// scionLayer is the SCION gopacket layer.
	scionLayer slayers.SCION
	hbhLayer   slayers.HopByHopExtn
	e2eLayer   slayers.EndToEndExtn
	udpLayer   slayers.UDP
	scmpLayer  slayers.SCMP
	// last is the last parsed layer, i.e. either &scionLayer, &hbhLayer or &e2eLayer
	lastLayer gopacket.DecodingLayer
)

func (c *connUDPBase) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	n, oobn, _, src, err := c.conn.ReadMsgUDP(b, c.rxOob)
	if oobn > 0 {
		goTime := time.Now()
		kTime, err := parseOOB(c.rxOob[:oobn])
		if err != nil {
			return n, src, err
		}
		timeDelay := goTime.Sub(kTime)
		log.Info("Reading Packet TS: ", "go ts", goTime.UnixNano(), "kernel ts", kTime.UnixNano(), "difference", timeDelay.Nanoseconds())
	}

	_, err = decodeLayers(b, &scionLayer, &hbhLayer, &e2eLayer, &udpLayer)
	if err == nil {
		if data := string(udpLayer.Payload); data == "Hello, world!" {
			log.Info(fmt.Sprintf("Reading packet: %v -> %v : \"%v\"", udpLayer.SrcPort, udpLayer.DstPort, data))
		}
	}

	return n, src, err
	//return c.conn.ReadFromUDP(b)
}

func (c *connUDPBase) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *connUDPBase) WriteTo(b []byte, dst *net.UDPAddr) (int, error) {
	_, err := decodeLayers(b, &scionLayer, &hbhLayer, &e2eLayer, &udpLayer)
	if err == nil {
		if data := string(udpLayer.Payload); data == "Hello, world!" {
			log.Info(fmt.Sprintf("Writing packet: %v -> %v : \"%v\"", udpLayer.SrcPort, udpLayer.DstPort, data))
		}
	}

	var n int

	if c.Remote != nil {
		n, err = c.conn.Write(b)
	} else {
		n, err = c.conn.WriteTo(b, dst)
	}

	if err2 := sockctrl.SockControl(c.conn, func(fd int) error {
		return readTxTimestamp(fd, c)
	}); err2 != nil {
		//log.Info("Failed to read TX timestamp", "err", err2)
	}

	return n, err
	//return c.conn.WriteTo(b, dst)
}

// We absolutely dont care about the actual data so we dont mind it being weirdly overwritten
var txbuff = make([]byte, 1<<16)

func readTxTimestamp(fd int, c *connUDPBase) error {
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

		kTime, err := parseOOB(c.txOob[:oobn])
		if err != nil {
			log.Info("Couldn't parse OOB data", "err", err)
			continue
		}

		log.Info("Writing Packet TS: ", "kernel ts", kTime.UnixNano())
		return nil
	}
	return nil
}

func parseOOB(oob []byte) (time.Time, error) {
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

// Temporarily Deprecated
func handleOOB(oob []byte) (time.Time, error) {
	sizeofCmsgHdr := syscall.CmsgLen(0)

	for sizeofCmsgHdr <= len(oob) {
		hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if hdr.Len < syscall.SizeofCmsghdr {
			return time.Time{}, serrors.New("Cmsg from ReadBatch has corrupted header length",
				"min", syscall.SizeofCmsghdr, "actual", hdr.Len)
		}
		if hdr.Len > uint64(len(oob)) {
			return time.Time{}, serrors.New("Cmsg from ReadBath longer than remaining buffer",
				"max", len(oob), "actual", hdr.Len)
		}
		if hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_TIMESTAMPNS {
			tv := *(*syscall.Timespec)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
			return time.Unix(tv.Sec, tv.Nsec), nil
		}
		// What we actually want is the padded length of the cmsg, but CmsgLen
		// adds a CmsgHdr length to the result, so we subtract that.
		oob = oob[syscall.CmsgLen(int(hdr.Len))-sizeofCmsgHdr:]
	}
	return time.Time{}, nil
}

// Read and parse OOB data
// Temporarily Deprecated
func handleOOBBatch(msgs Messages, timestamps []time.Time) (int, error) {
	sizeofCmsgHdr := syscall.CmsgLen(0)

	parsedOOBs := 0
	for _, msg := range msgs {
		oob := msg.OOB[:msg.NN]
		for sizeofCmsgHdr <= len(oob) {
			hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
			if hdr.Len < syscall.SizeofCmsghdr {
				return parsedOOBs, serrors.New("Cmsg from ReadBatch has corrupted header length",
					"min", syscall.SizeofCmsghdr, "actual", hdr.Len)
			}
			if hdr.Len > uint64(len(oob)) {
				return parsedOOBs, serrors.New("Cmsg from ReadBath longer than remaining buffer",
					"max", len(oob), "actual", hdr.Len)
			}
			if hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_TIMESTAMPNS {
				tv := *(*syscall.Timespec)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
				timestamps[parsedOOBs] = time.Unix(tv.Sec, tv.Nsec)
				parsedOOBs++
			}
			// What we actually want is the padded length of the cmsg, but CmsgLen
			// adds a CmsgHdr length to the result, so we subtract that.
			oob = oob[syscall.CmsgLen(int(hdr.Len))-sizeofCmsgHdr:]
		}
	}
	return parsedOOBs, nil
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
		// Allocate rxOob size
		//m[i].OOB = make([]byte, oobSize)
	}
	return m
}
