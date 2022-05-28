package conn

import (
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/sockctrl"
	"golang.org/x/net/ipv4"
	"net"
	"time"
)

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
		if od, ok := tsDataMap[pathId]; ok && !od.prevIngTs.IsZero() {
			offset = kTime.Sub(od.prevIngTs).Nanoseconds()
		}

		// TODO (daniele): CHECK IF OFFSETS ARE SIMILAR

		tsDataMap.addOrUpdateIngressTime(kTime, pathId)

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

		if od, ok := tsDataMap[pathId]; ok {
			log.Info("=========== Writer BATCH Data",
				"penult", od.penultIngTs.UnixNano(),
				"last", od.prevIngTs.UnixNano(),
				"egre", od.prevEgrTs.UnixNano())
		}

		if od, ok := tsDataMap[pathId]; ok && !od.penultIngTs.IsZero() && !od.prevEgrTs.IsZero() {
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
		//dumpByteSlice(buf)
		actScionHdrLen := scionLayer.HdrLen * 4
		dataStart := actScionHdrLen + 4
		offsetslice := buf[dataStart : dataStart+8]
		int64ToByteSlice(offset, offsetslice)
		//dumpByteSlice(buf)

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
