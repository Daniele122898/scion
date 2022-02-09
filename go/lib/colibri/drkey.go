// Copyright 2021 ETH Zurich
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

// Package colibri contains methods for the creation and verification of the colibri packet
// timestamp and validation fields.
package colibri

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	base "github.com/scionproto/scion/go/co/reservation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/drkey"
	dkut "github.com/scionproto/scion/go/lib/drkey/drkeyutil"
	"github.com/scionproto/scion/go/lib/serrors"
	colpath "github.com/scionproto/scion/go/lib/slayers/path/colibri"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/util"
)

func createAuthsForBaseRequest(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	req *BaseRequest) error {

	keys, err := getKeys(ctx, conn, req.Path.Steps, req.SrcHost)
	if err != nil {
		return err
	}

	// MAC and set authenticators inside request
	payload := make([]byte, minSizeBaseReq(req))
	serializeBaseRequest(payload, req)
	req.Authenticators, err = dkut.ComputeAuthenticators(payload, keys)
	return err
}

func createAuthsForE2EReservationSetup(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	req *E2EReservationSetup) error {

	keys, err := getKeys(ctx, conn, req.Path.Steps, req.SrcHost)
	if err != nil {
		return err
	}

	payload := make([]byte, minSizeE2ESetupReq(req))
	serializeE2EReservationSetup(payload, req)
	req.Authenticators, err = dkut.ComputeAuthenticators(payload, keys)
	return err
}

func validateResponseAuthenticators(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	res *E2EResponse, requestPath *base.TransparentPath, srcHost net.IP,
	reqTimestamp time.Time) error {

	if err := checkValidAuthenticatorsAndPath(res, requestPath); err != nil {
		return err
	}
	if err := checkEqualLength(res.Authenticators, requestPath); err != nil {
		return err
	}
	payloads, err := serializeResponse(res, requestPath, reqTimestamp)
	if err != nil {
		return err
	}
	return validateBasic(ctx, conn, payloads, res.Authenticators, requestPath, srcHost)
}

func validateResponseErrorAuthenticators(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	res *E2EResponseError, requestPath *base.TransparentPath, srcHost net.IP,
	reqTimestamp time.Time) error {

	if err := checkValidAuthenticatorsAndPath(res, requestPath); err != nil {
		return err
	}
	if err := checkEqualLength(res.Authenticators, requestPath); err != nil {
		return err
	}
	// because a failure can originate at any on-path-AS, skip ASes before its origin:
	originalAuthenticators := res.Authenticators
	originalSteps := requestPath.Steps
	defer func() {
		res.Authenticators = originalAuthenticators
		requestPath.Steps = originalSteps
	}()
	res.Authenticators = res.Authenticators[:res.FailedAS+1]
	requestPath.Steps = requestPath.Steps[:res.FailedAS+1]
	payloads := serializeResponseError(res, reqTimestamp)
	return validateBasic(ctx, conn, payloads, res.Authenticators, requestPath, srcHost)
}

func validateSetupErrorAuthenticators(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer,
	res *E2ESetupError, requestPath *base.TransparentPath, srcHost net.IP,
	reqTimestamp time.Time) error {

	if err := checkValidAuthenticatorsAndPath(res, requestPath); err != nil {
		return err
	}
	if err := checkEqualLength(res.Authenticators, requestPath); err != nil {
		return err
	}
	// because a failure can originate at any on-path AS, skip ASes before its origin:
	originalAuthenticators := res.Authenticators
	originalSteps := requestPath.Steps
	defer func() {
		res.Authenticators = originalAuthenticators
		requestPath.Steps = originalSteps
	}()
	res.Authenticators = res.Authenticators[:res.FailedAS+1]
	requestPath.Steps = requestPath.Steps[:res.FailedAS+1]
	payloads := serializeSetupError(res, reqTimestamp)
	return validateBasic(ctx, conn, payloads, res.Authenticators, requestPath, srcHost)
}

func getKeys(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer, steps []base.PathStep,
	srcHost net.IP) ([][]byte, error) {

	if len(steps) < 2 {
		return nil, serrors.New("wrong path in request")
	}
	return getKeysWithLocalIA(ctx, conn, steps[1:], steps[0].IA, srcHost)
}

func getKeysWithLocalIA(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer, steps []base.PathStep,
	srcIA addr.IA, srcHost net.IP) ([][]byte, error) {

	ias := make([]addr.IA, len(steps))
	for i, step := range steps {
		ias[i] = step.IA
	}
	return dkut.GetLvl2Keys(ctx, conn, drkey.AS2Host, "colibri",
		dkut.SlowIAs(srcIA), dkut.SlowHosts(addr.HostFromIP(srcHost)),
		dkut.FastIAs(ias...))
}

func minSizeBaseReq(req *BaseRequest) int {
	return req.Id.Len() + 1 + 4 + // ID + index + time_stamp
		+req.Path.Len() + // path
		16 + 16 // srcHost + dstHost
}

func minSizeE2ESetupReq(req *E2EReservationSetup) int {
	// BaseRequest + BW + Segment reservation IDs
	return minSizeBaseReq(&req.BaseRequest) + 1 + len(req.Segments)*reservation.IDSegLen
}

func serializeBaseRequest(buff []byte, req *BaseRequest) {
	minSize := minSizeBaseReq(req)
	assert(len(buff) >= minSize, "buffer too short (actual %d < minumum %d)",
		len(buff), minSize)
	offset := req.Id.Len()
	// ID, index and timestamp:
	req.Id.Read(buff[:offset]) // ignore errors (length was already checked)
	buff[offset] = byte(req.Index)
	offset++
	binary.BigEndian.PutUint32(buff[offset:], util.TimeToSecs(req.TimeStamp))
	offset += 4
	// path:
	req.Path.Serialize(buff[offset:], base.SerializeImmutable)
	offset += req.Path.Len()
	// src and dst hosts:
	copy(buff[offset:], req.SrcHost.To16())
	offset += 16
	copy(buff[offset:], req.DstHost.To16())
}

func serializeE2EReservationSetup(buff []byte, req *E2EReservationSetup) {
	minSize := minSizeE2ESetupReq(req)
	assert(len(buff) >= minSize, "buffer too short (actual %d < minumum %d)",
		len(buff), minSize)
	offset := minSizeBaseReq(&req.BaseRequest)
	serializeBaseRequest(buff[:offset], &req.BaseRequest)

	// BW and segments:
	buff[offset] = byte(req.RequestedBW)
	offset++
	for _, id := range req.Segments {
		id.Read(buff[offset:]) // ignore errors (length was already checked)
		offset += reservation.IDSegLen
	}
}

// serializeResponse returns the serialized versions of the response, one per AS in the path.
func serializeResponse(res *E2EResponse, path *base.TransparentPath, timestamp time.Time) (
	[][]byte, error) {

	colPath, ok := res.ColibriPath.Dataplane().(snetpath.Colibri)
	if !ok {
		return nil, serrors.New("unsupported non colibri path type",
			"path_type", common.TypeOf(res.ColibriPath.Dataplane()))
	}
	colibriPath := &colpath.ColibriPath{}
	if err := colibriPath.DecodeFromBytes(colPath.Raw); err != nil {
		return nil, serrors.WrapStr("received invalid colibri path", err)
	}

	timestampBuff := make([]byte, 4)
	binary.BigEndian.PutUint32(timestampBuff, util.TimeToSecs(timestamp))
	allHfs := colibriPath.HopFields
	payloads := make([][]byte, len(allHfs))
	for i := range path.Steps {
		colibriPath.InfoField.HFCount = uint8(len(allHfs) - i)
		colibriPath.HopFields = allHfs[i:]
		payloads[i] = make([]byte, 1+4+colibriPath.Len()) // marker + timestamp + path
		payloads[i][0] = 0                                // success marker
		copy(payloads[i][1:5], timestampBuff)
		if err := colibriPath.SerializeTo(payloads[i][5:]); err != nil {
			return nil, err
		}
	}
	return payloads, nil
}

// serializeResponseError serializes the response error and returns one payload per AS in the path.
func serializeResponseError(res *E2EResponseError, timestamp time.Time) [][]byte {
	message := ([]byte(res.Message))
	// failure marker + timestamp + failedAS (as uint8) + message
	payload := make([]byte, 1+4+1+len(message))
	payload[0] = 1 // failure marker
	binary.BigEndian.PutUint32(payload[1:5], util.TimeToSecs(timestamp))
	payload[5] = uint8(res.FailedAS)
	copy(payload[6:], message)

	payloads := make([][]byte, len(res.Authenticators))
	for i := range payloads {
		payloads[i] = payload
	}
	return payloads
}

// serializeSetupError serializes the setup error and returns one payload per AS in the path.
func serializeSetupError(res *E2ESetupError, timestamp time.Time) [][]byte {
	message := ([]byte(res.Message))
	// failure marker + timestamp + failedAS (as uint8) + message
	payload := make([]byte, 1+4+1+len(message))
	payload[0] = 1 // failure marker
	binary.BigEndian.PutUint32(payload[1:5], util.TimeToSecs(timestamp))
	payload[5] = uint8(res.FailedAS)
	copy(payload[6:], message)

	payloads := make([][]byte, len(res.Authenticators))
	for i := range payloads {
		trail := res.AllocationTrail[i:]
		// append trail to payload (convoluted due to the type cast to byte):
		payloads[i] = append(payload, make([]byte, len(trail))...)
		for j := range trail {
			payloads[i][len(payload)+j] = byte(trail[j])
		}
	}
	return payloads
}

func validateBasic(ctx context.Context, conn dkut.DRKeyGetLvl2Keyer, payloads [][]byte,
	authenticators [][]byte, requestPath *base.TransparentPath, srcHost net.IP) error {

	keys, err := getKeysWithLocalIA(ctx, conn, requestPath.Steps, requestPath.SrcIA(), srcHost)
	if err != nil {
		return err
	}

	ok, err := dkut.ValidateAuthenticators(payloads, keys, authenticators)
	if err != nil {
		return err
	}
	if !ok {
		return serrors.New("validation failed for response")
	}
	return nil
}

func checkValidAuthenticatorsAndPath(res interface{}, path *base.TransparentPath) error {
	if res == nil {
		return serrors.New("no response")
	}
	if path == nil {
		return serrors.New("no path")
	}
	return nil
}

func checkEqualLength(authenticators [][]byte, path *base.TransparentPath) error {
	if len(path.Steps) != len(authenticators) {
		return serrors.New("wrong lengths: |path| != |authenticators|",
			"path", len(path.Steps), "authenticators", len(authenticators))
	}
	return nil
}
