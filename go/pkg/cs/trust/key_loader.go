// Copyright 2020 Anapaya Systems
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

package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/log"
)

// LoadingRing is a key ring that loads the private keys from the configured
// directory.
type LoadingRing struct {
	Dir string
}

// PrivateKeys loads all private keys that are in PKCS#8 format from the directory.
func (r LoadingRing) PrivateKeys(ctx context.Context) ([]crypto.Signer, error) {
	files, err := filepath.Glob(filepath.Join(r.Dir, "*.key"))
	if err != nil {
		return nil, err
	}
	log.FromCtx(ctx).Debug("available keys:", "files", files)

	var signers []crypto.Signer
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			log.FromCtx(ctx).Info("Error reading key file", "file", file, "err", err)
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "PRIVATE KEY" {
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			continue
		}
		signers = append(signers, signer)
	}
	return signers, nil
}
