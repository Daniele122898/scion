package conn

import (
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/slayers"
	"golang.org/x/net/ipv4"
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
	goTime := time.Now()
	if n == 0 || err != nil {
		return 0, err
	}

	msgs[0].N = n
	msgs[0].Addr = src

	var (
		scionLayer slayers.SCION
		hbhLayer   slayers.HopByHopExtn
	)

	if _, err2 := decodeLayers(msgs[0].Buffers[0], &scionLayer, &hbhLayer); err2 == nil && hbhLayer.ExtLen == 7 {
		ingressId, _ := getIngressId(&scionLayer)
		// TODO (daniele): Re-Add after SW TS are fixed
		kTime, err2 := parseOOB(c.txOob[:oobn])
		if err2 != nil {
			kTime = goTime // Use go time as backup
			log.Info("Used Go time as backup")
		}
		//kTime = goTime
		op := hbhLayer.Options[0]
		offsetData := hbhoffset(op.OptData)
		offsetHeader, id := offsetData.parseOffsetHeaderData()
		pathId := string(id)

		// if od, ok := tsDataMap[pathId]; ok {
		// 	log.Info("=========== Read Batch Data",
		// 		"propenult", od.propenultIngTs.UnixNano(),
		// 		"propenult zero", od.propenultIngTs.IsZero(),
		// 		"penult", od.penultIngTs.UnixNano(),
		// 		"penult zero", od.penultIngTs.IsZero(),
		// 		"last", od.prevIngTs.UnixNano(),
		// 		"last zero", od.prevIngTs.IsZero(),
		// 		"egre", od.prevEgrTs.UnixNano(),
		// 		"egre zero", od.prevEgrTs.IsZero())
		// }

		var offset int64 = 0
		// if od, ok := tsDataMap[pathId]; ok && !od.penultIngTs.IsZero() && !od.propenultIngTs.IsZero() {
		// 	offset = od.penultIngTs.Sub(od.propenultIngTs).Nanoseconds()
		// 	offset = normalize(offset)
		// }
		if od, ok := tsDataMap[pathId]; ok && !od.prevIngTs.IsZero() && !od.penultIngTs.IsZero() {
			offset = od.prevIngTs.Sub(od.penultIngTs).Nanoseconds()
			offset = normalize(offset)

			od.checkRingConditions(&kTime, ingressId)
			od.repOffsets.addEntry(offsetHeader)
		}
		tsDataMap.addOrUpdateIngressTime(kTime, pathId)

		// TODO (daniele): CHECK IF OFFSETS ARE SIMILAR
		checkOffsetConditions(offsetHeader, offset, pathId, ingressId)

		log.Info("Reading Batch", "delta", offsetHeader-offset)
		log.Info("======== Reading Batch TS:",
			"offset", offset,
			"headoff", offsetHeader)
	}

	return 1, err
}

func (c *connUDPIPv4) WriteBatch(msgs Messages, flags int) (int, error) {

	var pathId string
	isOrigin := false
	for i := range msgs {
		var (
			scionLayer slayers.SCION
			hbhLayer   slayers.HopByHopExtn
		)

		if _, err2 := decodeLayers(msgs[i].Buffers[0], &scionLayer, &hbhLayer); err2 != nil || hbhLayer.ExtLen != 7 {
			continue
		}
		isOrigin = hbhLayer.ExtLen == 0
		// TODO (daniele): Check for the correct option type
		op := hbhLayer.Options[0]
		offsetData := hbhoffset(op.OptData)
		_, id := offsetData.parseOffsetHeaderData()
		pathId = string(id)

		// Calculate offset
		var offset int64 = 0

		// if od, ok := tsDataMap[pathId]; ok {
		// 	log.Info("=========== Writer BATCH Data",
		// 		"propenult", od.propenultIngTs.UnixNano(),
		// 		"propenult zero", od.propenultIngTs.IsZero(),
		// 		"penult", od.penultIngTs.UnixNano(),
		// 		"penult zero", od.penultIngTs.IsZero(),
		// 		"last", od.prevIngTs.UnixNano(),
		// 		"last zero", od.prevIngTs.IsZero(),
		// 		"egre", od.prevEgrTs.UnixNano(),
		// 		"egre zero", od.prevEgrTs.IsZero())
		// }

		goTime := time.Now()
		var offsetNoQueue int64 = 0
		if od, ok := tsDataMap[pathId]; ok && !od.propenultIngTs.IsZero() && !od.prevEgrTs.IsZero() {
			if isOrigin {
				offset = od.prevEgrTs.Sub(od.penultIngTs).Nanoseconds()
				offset = normalize(offset)
			} else {
				offset = od.prevEgrTs.Sub(od.propenultIngTs).Nanoseconds()
				offset = normalize(offset)
			}
			offsetNoQueue = goTime.Sub(od.prevEgrTs).Nanoseconds()
		}

		log.Info("======== Write Batch TS:",
			"offset", offset,
			"offsetnq", offsetNoQueue,
			"diff", offset-offsetNoQueue,
		)

		// TODO (daniele): Check against header offset for anomalities

		// Write our own offset data into it
		// This builds on the assumption that the WriteBatch function is mostly called in BR
		// while the usual dispatching happens using the WriteTo functions. This can be easily changed
		// by just adopting the code of the WriteTo function but for now this assumption works.
		buf := msgs[i].Buffers[0]
		//dumpByteSlice(buf)
		actScionHdrLen := scionLayer.HdrLen * 4
		dataStart := actScionHdrLen + 4
		offsetslice := buf[dataStart : dataStart+8]
		int64ToByteSlice(offset, offsetslice)
		//dumpByteSlice(buf)

	}
	n, err := c.pconn.WriteBatch(msgs, flags)

	// TODO (daniele): Remove this temporary measure
	getGoTxTimestamp(isOrigin, pathId)

	// if len(pathId) > 0 {
	// 	_ = sockctrl.SockControl(c.conn, func(fd int) error {
	// 		return readTxTimestamp(fd, &c.connUDPBase, false, pathId)
	// 	})
	// }

	return n, err
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
