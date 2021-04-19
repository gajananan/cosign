package cosign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/sigstore/pkg/signature"
)

const IntegrityShieldAnnotationMessage = "integrityshield.io/message"
const IntegrityShieldAnnotationSignature = "integrityshield.io/signature"
const IntegrityShieldAnnotationCertificate = "integrityshield.io/certificate"

// Verify does all the main cosign checks in a loop, returning validated payloads.
// If there were no payloads, we return an error.
func VerifyYaml(ctx context.Context, co CheckOpts, payloadPath string) ([]SignedPayload, error) {
	// Enforce this up front.
	if co.Roots == nil && co.PubKey == nil {
		return nil, errors.New("one of public key or cert roots is required")
	}
	// TODO: Figure out if we'll need a client before creating one.
	rekorClient, err := app.GetRekorClient(TlogServer())
	if err != nil {
		return nil, err
	}

	var allSignatures []SignedPayload

	// These are all the signatures attached to our image that we know how to parse.
	allSignatures, err = FetchYamlSignatures(ctx, payloadPath)
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

		if co.Tlog {
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
			uuid, err := sp.VerifyTlog(rekorClient, pemBytes)
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
