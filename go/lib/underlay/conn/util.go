package conn

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"golang.org/x/sys/unix"
)

type offsetRing struct {
	offsets    []int64
	runningSum int64
	rop        uint8
}

type pathOffsetData struct {
	propenultIngTs time.Time
	penultIngTs    time.Time
	prevIngTs      time.Time
	prevEgrTs      time.Time
	repOffsets     offsetRing
	counter        uint8
}

type offsetMap map[string]*pathOffsetData

var tsDataMap offsetMap = make(map[string]*pathOffsetData)
var mapLock sync.Mutex
var localIA addr.IA = 0

func SetLocalIA(ia addr.IA) {
	localIA = ia
}

func (o *offsetRing) addEntry(offset int64) {
	o.rop = (o.rop + 1) % 3
	o.runningSum -= o.offsets[o.rop]
	o.runningSum += offset
	o.offsets[o.rop] = offset
}

func (o *offsetRing) getLatest() int64 {
	return o.offsets[o.rop]
}

func (o *offsetRing) getOldest() int64 {
	return o.offsets[((o.rop + 1) % 3)]
}

func (o *offsetRing) get(index uint8) int64 {
	return o.offsets[((o.rop - index) % 3)]
}

func (p *pathOffsetData) checkRingConditions(ktime *time.Time, ingressId uint16) uint8 {
	var c uint8 = 0
	repSum := p.repOffsets.runningSum

	off := ktime.Sub(p.propenultIngTs).Nanoseconds()
	if off-repSum > offsetThresh {
		c += 1
	}

	repSum -= p.repOffsets.get(0)
	off = p.prevIngTs.Sub(p.propenultIngTs).Nanoseconds()
	if off-repSum > offsetThresh {
		c += 1
	}

	repSum -= p.repOffsets.get(1)
	off = p.penultIngTs.Sub(p.propenultIngTs).Nanoseconds()
	if off-repSum > offsetThresh {
		c += 1
	}

	p.counter += c

	return c
}

// Go only has builtin abs function for float64 :)
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
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

func byteSliceToInt32(b []byte) (int32, bool) {
	if len(b) < 4 {
		return 0, false
	}

	var val int32 = 0
	for i := 0; i < 4; i++ {
		val |= int32(b[3-i]) << (8 * i)
	}
	return val, true
}

func (data hbhoffset) parseOffsetHeaderData() (offset int64, id []byte) {
	id = data[8:]
	// parse int
	offset, _ = byteSliceToInt64(data[:8])
	return offset, id
}

func int64ToByteSlice(n int64, b []byte) {
	for i := 0; i < 8; i++ {
		b[7-i] = byte(n >> (8 * i))
	}
}

func int32ToByteSlice(n int32, b []byte) {
	for i := 0; i < 4; i++ {
		b[3-i] = byte(n >> (8 * i))
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

func getIngressId(scionLayer *slayers.SCION) (uint16, error) {
	ppath := scionLayer.Path.(*scion.Raw)
	curr, err := ppath.GetCurrentHopField()
	if err != nil {
		return 0, err
	}

	info, err := ppath.GetCurrentInfoField()
	if err != nil {
		return 0, err
	}

	var ingressId uint16 = 0
	if !info.ConsDir {
		ingressId = curr.ConsEgress
	} else {
		ingressId = curr.ConsIngress
	}

	return ingressId, nil
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

func checkOffsetConditions(headerOffset int64, measuredOffset int64, pathId string, ingressId uint16) {
	od, ok := tsDataMap[pathId]
	if !ok || headerOffset == 0 || measuredOffset == 0 {
		return
	}

	ts := time.Now()
	mapLock.Lock()
	defer mapLock.Unlock()
	delta := headerOffset - measuredOffset
	if delta > offsetThresh {
		// Potential Queueing Delay
		od.counter += 1
		if od.counter >= counterThresh {
			od.counter = 0
			log.Info("================================================== ALERT",
				"Reason", "Potential Queueing Delay",
				"delta", delta,
				"headerOffset", headerOffset,
				"measuredOffset", measuredOffset,
				"ts ns", ts.UnixNano(),
				"ingressId", ingressId,
				"IA", localIA.String())
		}
	} else if delta < -offsetThresh {
		// Potential Link health degradation
		od.counter += 1
		if od.counter >= counterThresh {
			od.counter = 0
			log.Info("================================================== ALERT",
				"Reason", "Potential Link Health Degradation",
				"delta", delta,
				"headerOffset", headerOffset,
				"measuredOffset", measuredOffset,
				"ts ns", ts.UnixNano(),
				"ingressId", ingressId,
				"IA", localIA.String())
		}
	} else {
		// Everything is fine
		if od.counter == 1 {
			od.counter -= 1
		} else if od.counter > 1 {
			od.counter -= 2
		}
	}
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

// Temporary function until we get SW TS to work
func getGoTxTimestamp(isOrigin bool, pathId string) {
	kTime := time.Now()

	tsDataMap.addOrUpdateEgressTime(kTime, pathId)
	// Very ugly hack to fix the current PoC SIG not having any ingress packets
	if isOrigin {
		// tsDataMap.addOrUpdateIngressTimeOrigin(kTime, pathId)
		tsDataMap.addOrUpdateIngressTime(kTime, pathId)
	}
}

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
		//kTime = time.Now()

		tsDataMap.addOrUpdateEgressTime(kTime, pathId)
		// Very ugly hack to fix the current PoC SIG not having any ingress packets
		if isOrigin {
			tsDataMap.addOrUpdateIngressTime(kTime, pathId)
		}
		return nil
	}
	return nil
}

func normalize(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
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
	//ts := &unix.Timespec{}
	//b := bytes.NewReader(data)
	//if err := binary.Read(b, binary.LittleEndian, ts); err != nil {
	//	return time.Time{}, err
	//}
	//return time.Unix(ts.Unix()), nil
	sec := int64(binary.LittleEndian.Uint64(data[0:8]))
	nsec := int64(binary.LittleEndian.Uint64(data[8:]))
	return time.Unix(sec, nsec), nil
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
	// mapLock.Lock()
	// defer mapLock.Unlock()
	if od, ok := m[key]; ok {
		od.prevEgrTs = ts
	} else {
		m[key] = &pathOffsetData{
			prevEgrTs:      ts,
			penultIngTs:    time.Time{},
			prevIngTs:      time.Time{},
			propenultIngTs: time.Time{},
			counter:        0,
			repOffsets: offsetRing{
				offsets:    make([]int64, 3),
				runningSum: 0,
				rop:        0,
			},
		}
	}
}

func (m offsetMap) addOrUpdateIngressTime(ts time.Time, key string) {
	// mapLock.Lock()
	// defer mapLock.Unlock()
	if od, ok := m[key]; ok {
		od.propenultIngTs = od.penultIngTs
		od.penultIngTs = od.prevIngTs
		od.prevIngTs = ts
	} else {
		m[key] = &pathOffsetData{
			prevIngTs:      ts,
			counter:        0,
			prevEgrTs:      time.Time{},
			penultIngTs:    time.Time{},
			propenultIngTs: time.Time{},
			repOffsets: offsetRing{
				offsets:    make([]int64, 3, 3),
				runningSum: 0,
				rop:        0,
			},
		}
	}
}
