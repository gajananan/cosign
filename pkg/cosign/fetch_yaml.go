//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cosign

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"

	gyaml "github.com/ghodss/yaml"
	"gopkg.in/yaml.v2"
)

func FetchYamlSignatures(ctx context.Context, payloadPath string) ([]SignedPayload, error) {

	var payload []byte
	var err error
	signatures := make([]SignedPayload, 1)
	if payloadPath != "" {

		payload, err = ioutil.ReadFile(filepath.Clean(payloadPath))
		m := make(map[interface{}]interface{})

		err = yaml.Unmarshal([]byte(payload), &m)
		if err != nil {
			fmt.Println("error: %v", err)
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

		//payloadOrigPath := strings.TrimRight(payloadPath, ".signed")
		//payloadOrigYaml, err := ioutil.ReadFile(filepath.Clean(payloadOrigPath))

		//payloadOrig, _ := gyaml.YAMLToJSON(payloadOrigYaml)
		decodedMsg, _ := base64.StdEncoding.DecodeString(mAnnotationMap[msgAnnoKey].(string))
		payloadOrig, _ := gyaml.YAMLToJSON(decodedMsg)
		base64sig := fmt.Sprint(mAnnotationMap[sigAnnoKey])

		sp := SignedPayload{
			Payload:         payloadOrig,
			Base64Signature: base64sig,
		}

		encoded := mAnnotationMap[certAnnoKey].(string)

		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			fmt.Println("decode error:", err)
			return nil, err
		}
		decoded = gzipDecompress(decoded)

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

func gzipDecompress(in []byte) []byte {
	buffer := bytes.NewBuffer(in)
	reader, err := gzip.NewReader(buffer)
	if err != nil {
		return in
	}
	output := bytes.Buffer{}
	output.ReadFrom(reader)
	return output.Bytes()
}
