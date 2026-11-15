// Package verified contains the opt-in saved-plan protocol, not an authentication mechanism.
package verified

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

const Protocol = "slack-import-plan/v1"
const SourceVersion = "terraform-resource/slack-import-plan-v1"
const DeadlineCapability = "slack-import-plan-deadline/v1"
const MaxDeadlineHorizon = 15 * time.Minute

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var environmentPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var versionPattern = regexp.MustCompile(`^Terraform v([0-9]+\.[0-9]+\.[0-9]+)$`)
var ErrInvalid = errors.New("verified plan operation failed")

// ParseDeadline accepts only the canonical UTC RFC3339Nano representation.
// The trusted gate supplies this bound; it does not establish authorization.
func ParseDeadline(s string, now time.Time) (time.Time, error) {
	deadline, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || deadline.UTC().Format(time.RFC3339Nano) != s || CheckDeadline(deadline, now) != nil {
		return time.Time{}, ErrInvalid
	}
	return deadline, nil
}

func CheckDeadline(deadline, now time.Time) error {
	if now.IsZero() || deadline.IsZero() || !now.Before(deadline) || deadline.After(now.Add(MaxDeadlineHorizon)) {
		return ErrInvalid
	}
	return nil
}

func ValidHash(s string) bool        { return hashPattern.MatchString(s) }
func ValidEnvironment(s string) bool { return environmentPattern.MatchString(s) }
func TerraformVersion(s string) (string, error) {
	first := strings.Split(s, "\n")[0]
	matches := versionPattern.FindStringSubmatch(first)
	if matches == nil {
		return "", ErrInvalid
	}
	return matches[1], nil
}
func Checksum(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", ErrInvalid
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", ErrInvalid
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func Verify(filename, expected string) error {
	if !ValidHash(expected) {
		return ErrInvalid
	}
	sum, err := Checksum(filename)
	if err != nil || sum != expected {
		return ErrInvalid
	}
	return nil
}
func WriteJSON(filename string, value interface{}) error {
	b, err := json.Marshal(value)
	if err != nil {
		return ErrInvalid
	}
	return WriteBytes(filename, append(b, '\n'))
}
func WriteBytes(filename string, b []byte) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrInvalid
	}
	_, err = f.Write(b)
	if closeErr := f.Close(); err != nil || closeErr != nil {
		os.Remove(filename)
		return ErrInvalid
	}
	return nil
}

type PlanMetadata struct {
	Protocol         string `json:"protocol"`
	Environment      string `json:"environment"`
	TerraformVersion string `json:"terraform_version"`
	BinarySHA256     string `json:"binary_sha256"`
	JSONSHA256       string `json:"json_sha256"`
	SourceVersion    string `json:"source_version"`
}
type ApplyResult struct {
	Protocol            string `json:"protocol"`
	Environment         string `json:"environment"`
	AppliedBinarySHA256 string `json:"applied_binary_sha256"`
	SourceVersion       string `json:"source_version"`
}

func DigestBytes(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
