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
	"crypto"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	gyaml "github.com/ghodss/yaml"
	"github.com/kr/pretty"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/pkg/errors"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/cosign/pkg/cosign/kms"
	"github.com/sigstore/sigstore/pkg/signature"
)

// VerifyCommand verifies a signature on a supplied container image
type SignYamlCommand struct {
	Upload      bool
	KeyRef      string
	KmsVal      string
	Annotations *map[string]interface{}
	PayloadPath string
	Yaml        bool
}

// Verify builds and returns an ffcli command
func SignYaml() *ffcli.Command {
	cmd := SignYamlCommand{}
	flagset := flag.NewFlagSet("cosign sign-yaml", flag.ExitOnError)
	annotations := annotationsMap{}

	flagset.StringVar(&cmd.KeyRef, "key", "", "path to the public key file, URL, or KMS URI")
	flagset.StringVar(&cmd.KmsVal, "kms", "", "sign via a private key stored in a KMS")
	flagset.BoolVar(&cmd.Upload, "upload", true, "whether to upload the signature")
	flagset.StringVar(&cmd.PayloadPath, "payload", "", "path to the yaml file")
	flagset.BoolVar(&cmd.Yaml, "yaml", true, "if it is yaml file")
	// parse annotations
	flagset.Var(&annotations, "a", "extra key=value pairs to sign")
	cmd.Annotations = &annotations.annotations

	return &ffcli.Command{
		Name:       "sign-yaml",
		ShortUsage: "cosign sign-yaml -key <key path>|<kms uri> [-payload <path>] [-a key=value] [-upload=true|false] [-f] <image uri> [-yaml=true|false]",
		ShortHelp:  `Sign the supplied yaml file.`,
		LongHelp: `Sign the supplied yaml file.

EXAMPLES
  # sign a container image with Google sign-in (experimental)
  COSIGN_EXPERIMENTAL=1 cosign sign-yaml -payload <yaml file> -yaml true

  # sign a container image with a local key pair file
  cosign sign-yaml -key cosign.pub -payload <yaml file> -yaml true

  # sign a container image and add annotations
  cosign sign-yaml -key cosign.pub -a key1=value1 -a key2=value2 -payload <yaml file> -yaml true

  # sign a container image with a key pair stored in Google Cloud KMS
  cosign sign-yaml -key gcpkms://projects/<PROJECT>/locations/global/keyRings/<KEYRING>/cryptoKeys/<KEY> -payload <yaml file> -yaml true`,
		FlagSet: flagset,
		Exec:    cmd.Exec,
	}
}

// Exec runs the verification command
func (c *SignYamlCommand) Exec(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return flag.ErrHelp
	}

	keyRef := c.KeyRef
	payloadPath := c.PayloadPath
	// The payload can be specified via a flag to skip generation.
	var payload []byte
	var payloadYaml []byte
	fmt.Fprintln(os.Stderr, "Using payload from:", payloadPath)
	payloadYaml, err := ioutil.ReadFile(filepath.Clean(payloadPath))
	payload, _ = gyaml.YAMLToJSON(payloadYaml)

	if err != nil {
		return errors.Wrap(err, "payload")
	}

	var signer signature.Signer
	var sig []byte
	var pemBytes []byte
	var cert, chain string
	if keyRef != "" {
		k, err := kms.Get(ctx, c.KmsVal)
		if err != nil {
			return err
		}
		signer = k
		if err != nil {
			return errors.Wrap(err, "getting public key")
		}
		pemBytes, err = cosign.PublicKeyPem(ctx, k)
		if err != nil {
			return err
		}
	} else {
		// Keyless!
		fmt.Fprintln(os.Stderr, "Generating ephemeral keys...")
		priv, err := cosign.GeneratePrivateKey()
		if err != nil {
			return errors.Wrap(err, "generating cert")
		}
		signer = signature.NewECDSASignerVerifier(priv, crypto.SHA256)
		fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")

		flow := fulcio.FlowNormal
		if !term.IsTerminal(0) {
			fmt.Fprintln(os.Stderr, "Non-interactive mode detected, using device flow.")
			flow = fulcio.FlowDevice
		}
		cert, chain, err = fulcio.GetCert(ctx, priv, flow) // TODO, use the chain.
		if err != nil {
			return errors.Wrap(err, "retrieving cert")
		}
		pemBytes = []byte(cert)
	}

	sig, err = signer.Sign(ctx, payload)
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
	if keyRef == "" {
		fmt.Println("Ceritificate Chain (issued and ca root):")
		fmt.Println("......................................")

		fmt.Println("chain", chain)
		fmt.Println("pemBytes", string(pemBytes))

		fmt.Println("......................................")
	}
	m := make(map[interface{}]interface{})

	err = yaml.Unmarshal([]byte(payloadYaml), &m)
	if err != nil {
		fmt.Errorf("error: %v", err)
	}
	pretty.Printf("\n%# v\n\n", m)
	fmt.Println("signature:", base64.StdEncoding.EncodeToString(sig))
	fmt.Println("cert", base64.StdEncoding.EncodeToString(pemBytes))
	fmt.Println("keyRef", keyRef)
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
		fmt.Println("there is no `metadata.annotations` in this payload")
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

	fmt.Println("......................................")
	fmt.Println("")
	fmt.Println("Signed yaml:")
	fmt.Println("")
	mapBytes, err := yaml.Marshal(m)

	err = ioutil.WriteFile(filepath.Clean(payloadPath+".signed"), mapBytes, 0644)

	out := make(map[interface{}]interface{})

	signed, _ := ioutil.ReadFile(filepath.Clean(payloadPath + ".signed"))

	err = yaml.Unmarshal(signed, &out)
	if err != nil {
		panic(err)
	}

	pretty.Printf("\n%# v\n\n", out)

	if !cosign.Experimental() {
		return nil
	}

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
	index, err := cosign.UploadTLog(sig, payload, rekorBytes)
	if err != nil {
		return err
	}
	fmt.Println("tlog entry created with index: ", index)
	return nil
}
