// Copyright 2021 The Rekor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cosign

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	gyaml "github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v2"
)

type SignedPayload struct {
	Base64Signature string
	Payload         []byte
	Cert            *x509.Certificate
	Chain           []*x509.Certificate
}

// TODO: marshal the cert correctly.
// func (sp *SignedPayload) MarshalJSON() ([]byte, error) {
// 	x509.Certificate.
// 	pem.EncodeToMemory(&pem.Block{
// 		Type: "CERTIFICATE",
// 		Bytes:
// 	})
// }

func Munge(desc v1.Descriptor) string {
	// sha256:... -> sha256-...
	munged := strings.ReplaceAll(desc.Digest.String(), ":", "-")
	munged += ".cosign"
	return munged
}

func FetchSignaturesYaml(ctx context.Context, payloadPath string) ([]SignedPayload, error) {

	var payload []byte
	var err error
	signatures := make([]SignedPayload, 1)
	if payloadPath != "" {

		fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
		payload, err = ioutil.ReadFile(filepath.Clean(payloadPath))
		m := make(map[interface{}]interface{})

		err = yaml.Unmarshal([]byte(payload), &m)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		//log.SetLevel(log.TraceLevel)

		mMeta, ok := m["metadata"]
		if !ok {
			return nil, fmt.Errorf("there is no `metadata` in this payload")
		}
		mMetaMap, ok := mMeta.(map[interface{}]interface{})
		if !ok {
			return nil, fmt.Errorf("`metadata` in this payload is not a yaml object")
		}
		mAnnotation, ok := mMetaMap["annotations"]
		if !ok {
			return nil, fmt.Errorf("there is no `metadata.annotations` in this payload")
		}
		mAnnotationMap, ok := mAnnotation.(map[interface{}]interface{})
		if !ok {
			return nil, fmt.Errorf("`metadata.annotations` in this payload is not a yaml object")
		}

		msgAnnoKey := IntegrityShieldAnnotationMessage
		sigAnnoKey := IntegrityShieldAnnotationSignature
		certAnnoKey := IntegrityShieldAnnotationCertificate
		log.Trace("----------")
		//log.Trace("payload json m", m)
		log.Trace("cert:", mAnnotationMap[certAnnoKey])
		log.Trace("msg:", mAnnotationMap[msgAnnoKey])
		log.Trace("sig:", mAnnotationMap[sigAnnoKey])
		log.Trace("----------")

		log.Trace("payloadPath", payloadPath)
		payloadOrigPath := strings.TrimRight(payloadPath, ".signed")
		log.Trace("payloadOrigPath", payloadOrigPath)
		payloadOrigYaml, err := ioutil.ReadFile(filepath.Clean(payloadOrigPath))
		payloadOrig, _ := gyaml.YAMLToJSON(payloadOrigYaml)
		base64sig := fmt.Sprint(mAnnotationMap[sigAnnoKey])
		log.Trace("payloadOrig", string(payloadOrig))
		log.Trace("--------------base64sig", base64sig)

		sp := SignedPayload{
			Payload:         payloadOrig,
			Base64Signature: base64sig,
		}

		encoded := mAnnotationMap[certAnnoKey].(string)

		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			log.Trace("decode error:", err)
			return nil, err
		}
		log.Trace("certPem", string(decoded))
		certPem := string(decoded)

		if certPem != "" {
			certs, err := LoadCerts(certPem)
			if err != nil {
				return nil, err
			}
			sp.Cert = certs[0]
		}

		signatures[0] = sp
	}

	return signatures, nil
}

func FetchSignatures(ctx context.Context, ref name.Reference) ([]SignedPayload, *v1.Descriptor, error) {
	targetDesc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, nil, err
	}

	// first, see if signatures exist in an alternate location
	dstRef, err := DestinationRef(ref, targetDesc)
	if err != nil {
		return nil, nil, err
	}
	sigImg, err := remote.Image(dstRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, nil, errors.Wrap(err, "remote image")
	}

	m, err := sigImg.Manifest()
	if err != nil {
		return nil, nil, errors.Wrap(err, "manifest")
	}

	g, ctx := errgroup.WithContext(ctx)
	signatures := make([]SignedPayload, len(m.Layers))
	sem := semaphore.NewWeighted(int64(runtime.NumCPU()))
	for i, desc := range m.Layers {
		i, desc := i, desc
		g.Go(func() error {
			if err := sem.Acquire(ctx, 1); err != nil {
				return err
			}
			defer sem.Release(1)
			base64sig, ok := desc.Annotations[sigkey]
			log.Trace("--------------base64sig", base64sig)
			if !ok {
				return nil
			}
			log.Trace("desc.Digest", desc.Digest)
			l, err := sigImg.LayerByDigest(desc.Digest)
			if err != nil {
				return err
			}
			log.Trace("l", l)
			// Compressed is a misnomer here, we just want the raw bytes from the registry.
			r, err := l.Compressed()
			if err != nil {
				return err

			}
			log.Trace("r", r)
			payload, err := ioutil.ReadAll(r)
			if err != nil {
				return err
			}
			sp := SignedPayload{
				Payload:         payload,
				Base64Signature: base64sig,
			}
			// We may have a certificate and chain
			certPem := desc.Annotations[certkey]
			log.Trace("certPem", certPem)
			if certPem != "" {
				certs, err := LoadCerts(certPem)
				if err != nil {
					return err
				}
				sp.Cert = certs[0]
			}
			chainPem := desc.Annotations[chainkey]
			if chainPem != "" {
				certs, err := LoadCerts(chainPem)
				if err != nil {
					return err
				}
				sp.Chain = certs
			}

			signatures[i] = sp
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}
	return signatures, &targetDesc.Descriptor, nil
}

func LoadCerts(pemStr string) ([]*x509.Certificate, error) {
	blocks := []*pem.Block{}
	pemBytes := []byte(pemStr)
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
		pemBytes = rest
	}

	certs := []*x509.Certificate{}
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
