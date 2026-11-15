package models

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

type OutRequest struct {
	Source Source    `json:"source"`
	Params OutParams `json:"params"`
}

type OutResponse struct {
	Version  Version  `json:"version"`
	Metadata Metadata `json:"metadata"`
}

type OutParams struct {
	SensitivePlan               bool   `json:"sensitive_plan,omitempty"`
	VerifiedPlan                bool   `json:"verified_plan,omitempty"`
	ExpectedPlanChecksum        string `json:"expected_plan_checksum,omitempty"`
	VerificationDeadline        string `json:"verification_deadline,omitempty"`
	verificationDeadlinePresent bool
	EnvName                     string `json:"env_name"`
	EnvNameFile                 string `json:"env_name_file"`
	GenerateRandomName          bool   `json:"generate_random_name"`
	Action                      string `json:"action,omitempty"` // optional
	Terraform
}

// UnmarshalJSON validates only the new deadline field strictly. Legacy fields
// retain the standard decoder's behavior and Terraform's embedded schema.
func (p *OutParams) UnmarshalJSON(b []byte) error {
	// A reused value must never carry a stale deadline into a new request,
	// including when the new JSON fails to decode.
	p.VerificationDeadline = ""
	p.verificationDeadlinePresent = false

	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil {
		return err
	}
	seen := false
	deadline := ""
	if delim, ok := token.(json.Delim); ok && delim == '{' {
		for d.More() {
			name, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := name.(string)
			if !ok {
				return errors.New("invalid verification_deadline")
			}
			var value json.RawMessage
			if err := d.Decode(&value); err != nil {
				return err
			}
			if strings.EqualFold(key, "verification_deadline") {
				if key != "verification_deadline" || seen || len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &deadline) != nil {
					return errors.New("invalid verification_deadline")
				}
				seen = true
			}
		}
		if _, err := d.Token(); err != nil {
			return err
		}
	}
	type plain OutParams
	decoded := plain(*p)
	if err := json.Unmarshal(b, &decoded); err != nil {
		return err
	}
	decoded.VerificationDeadline = deadline
	decoded.verificationDeadlinePresent = seen
	*p = OutParams(decoded)
	return nil
}

func (p OutParams) HasVerificationDeadline() bool {
	return p.verificationDeadlinePresent || p.VerificationDeadline != ""
}

const (
	DestroyAction = "destroy"
)
