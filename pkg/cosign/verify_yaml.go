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
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "embed" // To enable the `go:embed` directive.

	"github.com/pkg/errors"

	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

const IntegrityShieldAnnotationMessage = "integrityshield.io/message"
const IntegrityShieldAnnotationSignature = "integrityshield.io/signature"
const IntegrityShieldAnnotationCertificate = "integrityshield.io/certificate"

// Verify does all the main cosign checks in a loop, returning validated payloads.
// If there were no payloads, we return an error.
func VerifyYaml(ctx context.Context, co *CheckOpts, payloadPath string) ([]SignedPayload, error) {
	// Enforce this up front.
	if co.Roots == nil && co.PubKey == nil {
		return nil, errors.New("one of public key or cert roots is required")
	}
	// TODO: Figure out if we'll need a client before creating one.
	rekorClient, err := app.GetRekorClient(TlogServer())
	if err != nil {
		return nil, err
	}

	// These are all the signatures attached to our image that we know how to parse.
	allSignatures, err := FetchYamlSignatures(ctx, payloadPath)
	if err != nil {
		return nil, errors.Wrap(err, "fetching signatures")
	}

	validationErrs := []string{}
	checkedSignatures := []SignedPayload{}
	for _, sp := range allSignatures {
		switch {
		// We have a public key to check against.
		case co.PubKey != nil:
			if err := sp.VerifyKey(ctx, co.PubKey); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
		// If we don't have a public key to check against, we can try a root cert.
		case co.Roots != nil:
			// There might be signatures with a public key instead of a cert, though
			if sp.Cert == nil {
				validationErrs = append(validationErrs, "no certificate found on signature")
				continue
			}
			pub := &signature.ECDSAVerifier{Key: sp.Cert.PublicKey.(*ecdsa.PublicKey), HashAlg: crypto.SHA256}
			// Now verify the signature, then the cert.
			if err := sp.VerifyKey(ctx, pub); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
			if err := sp.TrustedCert(co.Roots); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}
		}

		// We can't check annotations without claims, both require unmarshalling the payload.
		if co.Claims {
			ss := &payload.SimpleContainerImage{}
			if err := json.Unmarshal(sp.Payload, ss); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}

			/*if err := sp.VerifyClaims(desc, ss); err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}*/

			if co.Annotations != nil {
				if !correctAnnotations(co.Annotations, ss.Optional) {
					validationErrs = append(validationErrs, "missing or incorrect annotation")
					continue
				}
			}
		}

		verified, err := sp.VerifyBundle()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to verify offline (%v), checking tlog instead...", err)
		}
		co.VerifyBundle = verified

		if co.Tlog && !verified {
			// Get the right public key to use (key or cert)
			var pemBytes []byte
			if co.PubKey != nil {
				pemBytes, err = PublicKeyPem(ctx, co.PubKey)
				if err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}
			} else {
				pemBytes = CertToPem(sp.Cert)
			}

			// Find the uuid then the entry.
			uuid, _, err := sp.VerifyTlog(rekorClient, pemBytes)
			if err != nil {
				validationErrs = append(validationErrs, err.Error())
				continue
			}

			// if we have a cert, we should check expiry
			if sp.Cert != nil {
				e, err := getTlogEntry(rekorClient, uuid)
				if err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}
				// Expiry check is only enabled with Tlog support
				if err := checkExpiry(sp.Cert, time.Unix(e.IntegratedTime, 0)); err != nil {
					validationErrs = append(validationErrs, err.Error())
					continue
				}
			}
		}

		// Phew, we made it.
		checkedSignatures = append(checkedSignatures, sp)
	}
	if len(checkedSignatures) == 0 {
		return nil, fmt.Errorf("no matching signatures:\n%s", strings.Join(validationErrs, "\n "))
	}
	return checkedSignatures, nil
}
