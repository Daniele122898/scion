// Copyright 2020 ETH Zurich
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

package grpc_test

import (
	"context"
	"log"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/xtest"
	sd_grpc "github.com/scionproto/scion/go/pkg/daemon/drkey/grpc"
	"github.com/scionproto/scion/go/pkg/grpc/mock_grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	mock_cppb "github.com/scionproto/scion/go/pkg/proto/control_plane/mock_control_plane"
	drkey_pb "github.com/scionproto/scion/go/pkg/proto/drkey"
)

func dialer(drkeyServer cppb.DRKeyIntraServiceServer) func(context.Context,
	string) (net.Conn, error) {
	bufsize := 1024 * 1024
	listener := bufconn.Listen(bufsize)

	server := grpc.NewServer()

	cppb.RegisterDRKeyIntraServiceServer(server, drkeyServer)

	go func() {
		if err := server.Serve(listener); err != nil {
			log.Fatal(err)
		}
	}()

	return func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}
}

func TestGetHostHost(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	now := time.Now().UTC()
	epochBegin, err := ptypes.TimestampProto(now)
	require.NoError(t, err)
	epochEnd, err := ptypes.TimestampProto(now.Add(24 * time.Hour))
	require.NoError(t, err)

	resp := &drkey_pb.HostHostResponse{
		Key:        xtest.MustParseHexString("c584cad32613547c64823c756651b6f5"),
		EpochBegin: epochBegin,
		EpochEnd:   epochEnd,
	}

	daemonSrv := mock_cppb.NewMockDRKeyIntraServiceServer(ctrl)
	daemonSrv.EXPECT().HostHost(gomock.Any(),
		gomock.Any()).Return(
		resp,
		nil,
	)

	conn, err := grpc.DialContext(context.Background(),
		"",
		grpc.WithInsecure(),
		grpc.WithContextDialer(dialer(daemonSrv)),
	)
	require.NoError(t, err)
	defer conn.Close()

	dialer := mock_grpc.NewMockDialer(ctrl)
	dialer.EXPECT().Dial(gomock.Any(), gomock.Any()).Return(conn, nil)

	fetcher := sd_grpc.Fetcher{
		Dialer: dialer,
	}

	meta := drkey.HostHostMeta{}
	_, err = fetcher.HostHostKey(context.Background(), meta)
	require.NoError(t, err)
}
