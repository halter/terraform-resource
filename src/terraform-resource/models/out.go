package models

import (
	"encoding/json"
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

// UnmarshalJSON retains presence, including empty or null, so a deadline sent
// without verification cannot be silently ignored. Other fields retain the
// standard decoder's behavior and Terraform's existing embedded schema.
func (p *OutParams) UnmarshalJSON(b []byte) error {
	type plain OutParams
	decoded := plain(*p)
	if err := json.Unmarshal(b, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	*p = OutParams(decoded)
	for key := range fields {
		if strings.EqualFold(key, "verification_deadline") {
			p.verificationDeadlinePresent = true
		}
	}
	return nil
}

func (p OutParams) HasVerificationDeadline() bool {
	return p.verificationDeadlinePresent || p.VerificationDeadline != ""
}

const (
	DestroyAction = "destroy"
)
