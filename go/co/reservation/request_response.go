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
	"time"

	"github.com/scionproto/scion/go/lib/colibri/reservation"
	col "github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

type MsgId struct {
	ID        col.ID
	Index     col.IndexNumber
	Timestamp time.Time
}

// Request is the base struct for any type of COLIBRI segment request.
// It contains a reference to the reservation it requests, or nil if not yet created.
type Request struct {
	MsgId
	Path *TransparentPath // the path to the destination. It represents the hops of the reservation.
}

// NewRequest constructs the segment Request type.
func NewRequest(ts time.Time, id *reservation.ID, idx reservation.IndexNumber,
	path *TransparentPath) (*Request, error) {

	if id == nil {
		return nil, serrors.New("new segment request with nil ID")
	}
	return &Request{
		MsgId: MsgId{
			Timestamp: ts,
			ID:        *id,
			Index:     idx,
		},
		Path: path,
	}, nil
}

// Validate ensures the data in the request is consistent. Calling methods on the request
// before a call to Validate may result in invalid behavior or panic.
func (r *Request) Validate() error {
	if err := r.Path.Validate(); err != nil {
		return serrors.WrapStr("bad path in request", err)
	}
	return r.ValidateIgnorePath()
}

func (r *Request) ValidateIgnorePath() error {
	if r.ID.ASID == 0 {
		return serrors.New("bad AS id in request", "asid", r.ID.ASID)
	}
	return nil
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

type Response interface {
	isResponse_SuccessFailure()
	Success() bool
}

type ResponseSuccess struct{}

func (r *ResponseSuccess) isResponse_SuccessFailure() {}
func (r *ResponseSuccess) Success() bool              { return true }

type ResponseFailure struct {
	Message    string
	FailedStep uint8
}

func (r *ResponseFailure) isResponse_SuccessFailure() {}
func (r *ResponseFailure) Success() bool              { return false }
