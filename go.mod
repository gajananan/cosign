module github.com/gajananan/cosign

go 1.16

require (
	github.com/cyberphone/json-canonicalization v0.0.0-20210303052042-6bc126869bf4
	github.com/go-openapi/runtime v0.19.28
	github.com/go-openapi/strfmt v0.20.1
	github.com/go-openapi/swag v0.19.15
	github.com/go-piv/piv-go v1.7.0
	github.com/google/go-cmp v0.5.5
	github.com/google/go-containerregistry v0.5.1
	github.com/google/trillian v1.3.14-0.20210413093047-5e12fb368c8f
	github.com/manifoldco/promptui v0.8.0
	github.com/open-policy-agent/opa v0.28.0
	github.com/peterbourgon/ff/v3 v3.0.0
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v0.0.0-00010101000000-000000000000
	github.com/sigstore/fulcio v0.0.0-20210405115948-e7630f533fca
	github.com/sigstore/rekor v0.1.2-0.20210428010952-9e3e56d52dd0
	github.com/sigstore/sigstore v0.0.0-20210427115853-11e6eaab7cdc
	github.com/stretchr/testify v1.7.0
	github.com/theupdateframework/go-tuf v0.0.0-20201230183259-aee6270feb55
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/term v0.0.0-20210422114643-f5beecf764ed
)

replace (
	github.com/sigstore/cosign => ./
	github.com/sigstore/rekor => github.com/sigstore/rekor v0.1.2-0.20210519014330-b5480728bde6
)
