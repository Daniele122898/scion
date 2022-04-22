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

package reservation

import (
	"encoding/binary"
	"time"

	"github.com/scionproto/scion/go/lib/colibri/reservation"
	col "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
	"github.com/scionproto/scion/go/lib/util"
)

type MsgId struct {
	ID        col.ID
	Index     col.IndexNumber
	Timestamp time.Time
}

func (m *MsgId) Len() int {
	return m.ID.Len() + 1 + 4
}

func (m *MsgId) Serialize(buff []byte) {
	m.ID.Read(buff)
	buff[m.ID.Len()] = byte(m.Index)
	binary.BigEndian.PutUint32(buff[m.ID.Len()+1:], util.TimeToSecs(m.Timestamp))
}

// Request is the base struct for any type of COLIBRI segment request.
// It contains a reference to the reservation it requests, or nil if not yet created.
type Request struct {
	MsgId
	Path           *TransparentPath // the path to the destination (hops of the reservation).
	Authenticators [][]byte         // one MAC per transit AS created by the initiator AS
}

// NewRequest constructs the segment Request type.
// If the authenticators argument is nil, a new and empty authenticators field is constructed.
func NewRequest(ts time.Time, id *reservation.ID, idx reservation.IndexNumber,
	path *TransparentPath) *Request {

	var authenticators [][]byte
	if path == nil {
		path = &TransparentPath{}
	}
	if path.RawPath == nil {
		path.RawPath = &empty.Path{}
	}
	if len(path.Steps) > 0 {
		authenticators = make([][]byte, len(path.Steps)-1)
	}
	return &Request{
		MsgId: MsgId{
			Timestamp: ts,
			ID:        *id,
			Index:     idx,
		},
		Path:           path,
		Authenticators: authenticators,
	}
}

// Validate ensures the data in the request is consistent. Calling methods on the request
// before a call to Validate may result in invalid behavior or panic.
func (r *Request) Validate() error {
	if err := r.Path.Validate(); err != nil {
		return serrors.WrapStr("bad path in request", err)
	}
	if len(r.Authenticators) != len(r.Path.Steps)-1 {
		return serrors.New("inconsistent number of authenticators",
			"auth_count", len(r.Authenticators), "path_len", len(r.Path.Steps))
	}
	if r.ID.ASID == 0 {
		return serrors.New("bad AS id in request", "asid", r.ID.ASID)
	}
	return nil
}

func (r *Request) Len() int {
	return r.MsgId.Len() + r.Path.Len()
}

func (r *Request) Serialize(buff []byte, options SerializeOptions) {
	offset := r.MsgId.Len()
	r.MsgId.Serialize(buff[:offset])
	r.Path.Serialize(buff[offset:], options)
}

func (r *Request) IsFirstAS() bool {
	return r.Path.CurrentStep == 0
}

func (r *Request) IsLastAS() bool { // override the use of the RequestMetadata.path with PathToDst
	return r.Path.CurrentStep >= len(r.Path.Steps)-1
}

// Ingress returns the ingress interface of this step for this request.
// Do not call Ingress without validating the request first.
func (r *Request) Ingress() uint16 {
	p := r.Path
	return p.Steps[p.CurrentStep].Ingress
}

// Egress returns the egress interface of this step for this request.
// Do not call Egress without validating the request first.
func (r *Request) Egress() uint16 {
	p := r.Path
	return p.Steps[p.CurrentStep].Egress
}

// CurrentValidatorField returns the validator field that contains the MAC used to authenticate
// the request by the initiator AS, for the current in-transit AS.
// Note that there doesn't exist a field for the initiator AS, as it is itself that authenticates.
func (r *Request) CurrentValidatorField() []byte {
	if r.Path.CurrentStep == 0 {
		return nil
	}
	return r.Authenticators[r.Path.CurrentStep-1]
}

type Response interface {
	isResponse_SuccessFailure()

	GetAuthenticators() [][]byte
	SetAuthenticator(currentStep int, authenticator []byte)
	GetTimestamp() time.Time
	Success() bool
	ToRaw() []byte
}

type AuthenticatedResponse struct {
	Timestamp      time.Time
	Authenticators [][]byte
}

func (r *AuthenticatedResponse) Serialize(buff []byte) {
	binary.BigEndian.PutUint32(buff, util.TimeToSecs(r.Timestamp))
}
func (r *AuthenticatedResponse) GetAuthenticators() [][]byte {
	return r.Authenticators
}

// SetAuthenticator sets the authenticator to the step-1 position. This is so because
// it expects to have one less authenticator than steps present in the path.
func (r *AuthenticatedResponse) SetAuthenticator(currentStep int, authenticator []byte) {
	r.Authenticators[currentStep-1] = authenticator
}

type ResponseSuccess struct {
	AuthenticatedResponse
}

func (r *ResponseSuccess) isResponse_SuccessFailure() {}
func (r *ResponseSuccess) Success() bool              { return true }
func (r *ResponseSuccess) ToRaw() []byte {
	buff := make([]byte, 5)
	buff[0] = 0
	r.Serialize(buff[1:5])
	return buff
}
func (r *ResponseSuccess) GetTimestamp() time.Time {
	return r.Timestamp
}

type ResponseFailure struct {
	AuthenticatedResponse
	FailedStep uint8
	Message    string
}

func (r *ResponseFailure) isResponse_SuccessFailure() {}
func (r *ResponseFailure) Success() bool              { return false }
func (r *ResponseFailure) ToRaw() []byte {
	buff := make([]byte, 1+4+1+len(r.Message)) // marker + timestamp + failed_step + message
	buff[0] = 1
	r.Serialize(buff[1:5])
	buff[5] = r.FailedStep
	copy(buff[6:], []byte(r.Message))
	return buff
}
func (r *ResponseFailure) GetTimestamp() time.Time {
	return r.Timestamp
}
