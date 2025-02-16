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

package trust_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/mock_trust"
)

func TestLoadX509KeyPair(t *testing.T) {
	if *updateNonDeterministic {
		t.Skip("test crypto is being updated")
	}

	getChain := func(t *testing.T) []*x509.Certificate {
		return xtest.LoadChain(t,
			filepath.Join(goldenDir, "ISD1/ASff00_0_110/crypto/as/ISD1-ASff00_0_110.pem"))
	}

	trc := xtest.LoadTRC(t, filepath.Join(goldenDir, "ISD1/trcs/ISD1-B1-S1.trc"))
	key := loadSigner(t, filepath.Join(goldenDir, "ISD1/ASff00_0_110/crypto/as/cp-as.key"))

	chain := getChain(t)
	longer := getChain(t)
	longer[0].NotAfter = longer[0].NotAfter.Add(time.Hour)
	longer[0].SubjectKeyId = []byte("longer")

	shorter := getChain(t)
	shorter[0].NotAfter = shorter[0].NotAfter.Add(-time.Hour)
	shorter[0].SubjectKeyId = []byte("shorter")

	testCases := map[string]struct {
		keyLoader    func(mctrcl *gomock.Controller) trust.KeyRing
		db           func(mctrcl *gomock.Controller) trust.DB
		extKeyUsage  x509.ExtKeyUsage
		assertFunc   assert.ErrorAssertionFunc
		expectedCert func() *tls.Certificate
	}{
		"valid": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain}, nil,
				)
				return db
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(chain))
				for i := range chain {
					certificate[i] = chain[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        chain[0],
				}
			},
		},
		"newest": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}

				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain, longer, shorter}, nil,
				)
				return db
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(longer))
				for i := range longer {
					certificate[i] = longer[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        longer[0],
				}
			},
		},
		"select best from grace": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				cert := chain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}

				trc2 := xtest.LoadTRC(t, filepath.Join(goldenDir, "ISD1/trcs/ISD1-B1-S1.trc"))
				trc2.TRC.ID.Serial = 2
				trc2.TRC.Validity.NotBefore = time.Now()
				trc2.TRC.GracePeriod = 5 * time.Minute

				roots, err := trc2.TRC.RootCerts()
				require.NoError(t, err)
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				for _, root := range roots {
					root.PublicKey = key.Public()
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc2, nil,
				)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1, Serial: 1, Base: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{chain, longer, shorter}, nil,
				)
				return db
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.NoError,
			expectedCert: func() *tls.Certificate {
				certificate := make([][]byte, len(chain))
				for i := range chain {
					certificate[i] = longer[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        longer[0],
				}
			},
		},
		"no keys": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				return mock_trust.NewMockDB(mctrl)
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"rsa key": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)

				priv, err := rsa.GenerateKey(rand.Reader, 512)
				require.NoError(t, err)

				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{priv}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				return db
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"no chain found": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				cert := chain[0]
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{},
					cppki.TRCID{ISD: 1}).Return(trc, nil)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(nil, nil)
				return db
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.SignedTRC error": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{},
					cppki.TRCID{ISD: 1}).Return(
					cppki.SignedTRC{}, serrors.New("fail"))
				return db
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.SignedTRC not found": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					cppki.SignedTRC{}, nil)
				return db
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"db.Chain error": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				db := mock_trust.NewMockDB(mctrl)
				cert := chain[0]
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{},
					cppki.TRCID{ISD: 1}).Return(trc, nil)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					nil, serrors.New("fail"),
				)
				return db
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
		"correct EKU": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				invalidExtChain := getChain(t)
				invalidExtChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				validExtChain := getChain(t)
				validExtChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				cert := validExtChain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{invalidExtChain, validExtChain}, nil,
				)
				return db
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.NoError,
			expectedCert: func() *tls.Certificate {
				validExtChain := getChain(t)
				validExtChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageServerAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				certificate := make([][]byte, len(validExtChain))
				for i := range validExtChain {
					certificate[i] = validExtChain[i].Raw
				}
				return &tls.Certificate{
					Certificate: certificate,
					PrivateKey:  key,
					Leaf:        validExtChain[0],
				}
			},
		},
		"wrong EKU": {
			keyLoader: func(mctrl *gomock.Controller) trust.KeyRing {
				loader := mock_trust.NewMockKeyRing(mctrl)
				loader.EXPECT().PrivateKeys(gomock.Any()).Return(
					[]crypto.Signer{key}, nil,
				)
				return loader
			},
			db: func(mctrl *gomock.Controller) trust.DB {
				extChain := getChain(t)
				extChain[0].ExtKeyUsage = []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
					x509.ExtKeyUsageTimeStamping,
				}
				cert := extChain[0]
				db := mock_trust.NewMockDB(mctrl)
				matcher := chainQueryMatcher{
					ia:   xtest.MustParseIA("1-ff00:0:110"),
					skid: cert.SubjectKeyId,
				}
				db.EXPECT().SignedTRC(ctxMatcher{}, cppki.TRCID{ISD: 1}).Return(
					trc, nil,
				)
				db.EXPECT().Chains(gomock.Any(), matcher).Return(
					[][]*x509.Certificate{extChain}, nil,
				)
				return db
			},
			extKeyUsage: x509.ExtKeyUsageServerAuth,
			assertFunc:  assert.Error,
			expectedCert: func() *tls.Certificate {
				return nil
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			//t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			provider := trust.X509KeyPairProvider{
				IA:     xtest.MustParseIA("1-ff00:0:110"),
				DB:     tc.db(mctrl),
				Loader: tc.keyLoader(mctrl),
			}
			tlsCert, err := provider.LoadX509KeyPair(context.Background(), tc.extKeyUsage)
			tc.assertFunc(t, err)
			if err == nil {
				assert.Equal(t, tc.expectedCert().Leaf.SubjectKeyId, tlsCert.Leaf.SubjectKeyId)
			}

		})
	}
}

func loadSigner(t *testing.T, file string) crypto.Signer {
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		panic("no valid private key block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key.(crypto.Signer)
}
