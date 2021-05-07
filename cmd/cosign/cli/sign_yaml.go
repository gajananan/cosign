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

package cli

import (
	"context"
	_ "crypto/sha256" // for `crypto.SHA256`
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	gyaml "github.com/ghodss/yaml"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"

	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	"github.com/sigstore/sigstore/pkg/signature"
)

// VerifyCommand verifies a signature on a supplied container image
type SignYamlCommand struct {
	Upload      bool
	KeyRef      string
	Sk          bool
	Annotations *map[string]interface{}
	PayloadPath string
	Pf          cosign.PassFunc
}

func SignYaml() *ffcli.Command {

	cmd := SignYamlCommand{}
	flagset := flag.NewFlagSet("cosign sign-yaml", flag.ExitOnError)
	annotations := annotationsMap{}

	flagset.StringVar(&cmd.KeyRef, "key", "", "path to the public key file, URL, or KMS URI")
	flagset.BoolVar(&cmd.Sk, "sk", false, "whether to use a hardware security key")
	flagset.BoolVar(&cmd.Upload, "upload", true, "whether to upload the signature")
	flagset.StringVar(&cmd.PayloadPath, "payload", "", "path to the yaml file")

	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	return &ffcli.Command{
		Name:       "sign-yaml",
		ShortUsage: "cosign sign-yaml -key <key path>|<kms uri> [-payload <path>] [-a key=value] [-upload=true|false] [-f] <image uri>",
		ShortHelp:  `Sign the supplied yaml file.`,
		LongHelp: `Sign the supplied yaml file.

EXAMPLES
  # sign a container image with Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign sign-yaml -payload <yaml file> 

  # sign a container image with a local key pair file
  cosign sign-yaml -key cosign.pub -payload <yaml file> 

  # sign a container image and add annotations
  cosign sign-yaml -key cosign.pub -a key1=value1 -a key2=value2 -payload <yaml file>

  # sign a container image with a key pair stored in Google Cloud KMS
  cosign sign-yaml -key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> -payload <yaml file>`,
		FlagSet: flagset,
		Exec:    cmd.Exec,
	}

}

func (c *SignYamlCommand) Exec(ctx context.Context, args []string) error {

	// A key file or token is required unless we're in experimental mode!
	if cosign.Experimental() {
		if nOf(c.KeyRef, c.Sk) > 1 {
			return &KeyParseError{}
		}
	} else {
		if !oneOf(c.KeyRef, c.Sk) {
			return &KeyParseError{}
		}
	}

	//remoteAuth := remote.WithAuthFromKeychain(authn.DefaultKeychain)

	keyRef := c.KeyRef
	payloadPath := c.PayloadPath
	//pf := c.Pf
	// The payload can be specified via a flag to skip generation.
	var payload []byte
	var payloadYaml []byte

	payloadYaml, err := ioutil.ReadFile(filepath.Clean(payloadPath))
	payload, _ = gyaml.YAMLToJSON(payloadYaml)

	if err != nil {
		return errors.Wrap(err, "payload")
	}

	var signer signature.Signer
	//var dupeDetector signature.Verifier
	var cert string
	var pemBytes []byte
	switch {
	case c.Sk:
		sk, err := pivkey.NewSignerVerifier()
		if err != nil {
			return err
		}
		signer = sk
		//dupeDetector = sk
		pemBytes, err = cosign.PublicKeyPem(ctx, sk)
		if err != nil {
			return err
		}
	case c.KeyRef != "":
		k, err := signerVerifierFromKeyRef(ctx, c.KeyRef, c.Pf)
		if err != nil {
			return errors.Wrap(err, "reading key")
		}
		signer = k
		//dupeDetector = k
	default: // Keyless!
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		k, err := fulcio.NewSigner(ctx)
		if err != nil {
			return errors.Wrap(err, "getting key from Fulcio")
		}
		signer = k
		cert, _ = k.Cert, k.Chain
		pemBytes = []byte(cert)
	}

	sig, _, err := signer.Sign(ctx, payload)
	if err != nil {
		return errors.Wrap(err, "signing")
	}

	if !c.Upload {
		fmt.Println(base64.StdEncoding.EncodeToString(sig))
		return nil
	}

	fmt.Println("----------------------")
	fmt.Println("Yaml Signing Completed !!!")
	fmt.Println("----------------------")

	m := make(map[interface{}]interface{})

	err = yaml.Unmarshal([]byte(payloadYaml), &m)
	if err != nil {
		fmt.Errorf("error: %v", err)
	}
	mMeta, ok := m["metadata"]
	if !ok {
		return fmt.Errorf("there is no `metadata` in this payload")
	}
	mMetaMap, ok := mMeta.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("`metadata` in this payload is not a yaml object")
	}
	mAnnotation, ok := mMetaMap["annotations"]
	if !ok {
		mAnnotation = make(map[interface{}]interface{})
	}
	mAnnotationMap, ok := mAnnotation.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("`metadata.annotations` in this payload is not a yaml object")
	}

	msgAnnoKey := cosign.IntegrityShieldAnnotationMessage
	sigAnnoKey := cosign.IntegrityShieldAnnotationSignature
	certAnnoKey := cosign.IntegrityShieldAnnotationCertificate
	mAnnotationMap[sigAnnoKey] = base64.StdEncoding.EncodeToString(sig)
	mAnnotationMap[msgAnnoKey] = base64.StdEncoding.EncodeToString(payloadYaml)

	if keyRef == "" {
		mAnnotationMap[certAnnoKey] = base64.StdEncoding.EncodeToString(pemBytes)
	}
	m["metadata"].(map[interface{}]interface{})["annotations"] = mAnnotationMap

	mapBytes, err := yaml.Marshal(m)

	err = ioutil.WriteFile(filepath.Clean(payloadPath+".signed"), mapBytes, 0644)

	out := make(map[interface{}]interface{})

	signed, _ := ioutil.ReadFile(filepath.Clean(payloadPath + ".signed"))

	err = yaml.Unmarshal(signed, &out)
	if err != nil {
		panic(err)
	}

	/*
		// sha256:... -> sha256-...
		dstRef, err := cosign.DestinationRef(ref, get)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Pushing signature to:", dstRef.String())
		uo := cosign.UploadOpts{
				Cert:         string(cert),
				Chain:        string(chain),
				DupeDetector: dupeDetector,
				RemoteOpts:   []remote.Option{remoteAuth},
			}

		if !cosign.Experimental() {
			_, err := cosign.Upload(ctx, sig, payload, dstRef, uo)
			return err
		}
	*/

	// Upload the cert or the public key, depending on what we have
	var rekorBytes []byte
	if cert != "" {
		rekorBytes = []byte(cert)
	} else {
		pemBytes, err := cosign.PublicKeyPem(ctx, signer)
		if err != nil {
			return nil
		}
		rekorBytes = pemBytes
	}

	entry, err := cosign.UploadTLog(sig, payload, rekorBytes)
	if err != nil {
		return err
	}
	fmt.Println("tlog entry created with index: ", *entry.LogIndex)
	/*
		bund, err := bundle(entry)
		if err != nil {
			return errors.Wrap(err, "bundle")
		}
			uo.Bundle = bund
			uo.AdditionalAnnotations = annotations(entry)
			if _, err = cosign.Upload(ctx, sig, payload, dstRef, uo); err != nil {
				return errors.Wrap(err, "uploading")
			}
	*/
	return nil
}

/*
func bundle(entry *models.LogEntryAnon) (*cosign.Bundle, error) {
	if entry.Verification == nil {
		return nil, nil
	}
	return &cosign.Bundle{
		SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
		Body:                 entry.Body,
		IntegratedTime:       entry.IntegratedTime,
		LogIndex:             entry.LogIndex,
	}, nil
}

func annotations(entry *models.LogEntryAnon) map[string]string {
	annts := map[string]string{}
	if bund, err := bundle(entry); err == nil && bund != nil {
		contents, _ := json.Marshal(bund)
		annts[cosign.BundleKey] = string(contents)
	}
	return annts
}
*/
