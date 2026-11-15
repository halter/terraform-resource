package verified_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	resourcein "github.com/ljfranklin/terraform-resource/in"
	"github.com/ljfranklin/terraform-resource/models"
	"github.com/ljfranklin/terraform-resource/out"
	"github.com/ljfranklin/terraform-resource/verified"
)

const fakeCLI = `#!/bin/sh
if [ "${FAKE_RECORD:-}" = "1" ]; then printf 'CALL:%s\n' "$1" >> "$FAKE_LOG"; fi
if [ -n "${TF_LOG:-}${TF_LOG_PATH:-}${TF_LOG_PROVIDER:-}${TF_CLI_ARGS:-}${TF_CLI_ARGS_plan:-}${TF_REATTACH_PROVIDERS:-}" ]; then echo ENV-LEAK >> "$FAKE_LOG"; fi
case "$1:$2" in plan:*|apply:*|workspace:select|workspace:new|workspace:list) if [ -n "${TF_WORKSPACE:-}" ]; then echo WORKSPACE-LEAK >> "$FAKE_LOG"; fi;; esac
if [ "$FAKE_FAIL" = "$1" ]; then echo 'PRIVATE-CANARY' >&2; echo 'PRIVATE-CANARY'; exit 1; fi
case "$1" in
init) exit 0;;
workspace) case "$2" in list) printf '* tools\n  tools-plan\n';; esac; exit 0;;
plan) for arg in "$@"; do case "$arg" in -out=*) printf fixture-plan > "${arg#-out=}";; esac; done; echo PRIVATE-CANARY; echo PRIVATE-CANARY >&2;;
show) echo '{"synthetic":"PRIVATE-CANARY"}'; echo PRIVATE-CANARY >&2;;
output) printf '{"plan_content":{"value":"%s"},"plan_content_json":{"value":"%s"}}' "${FAKE_PLAN_BASE64:-Zml4dHVyZS1wbGFu}" "${FAKE_JSON_BASE64:-H4sIAAAAAAACE6tWKq7MK8lILclMVrJSCgjyDHMMcdV1dvRzDIpUquUCAMseSHAfAAAA}";;
apply) for arg in "$@"; do case "$arg" in */plan) echo APPLY >> "$FAKE_LOG";; esac; done; echo PRIVATE-CANARY; echo PRIVATE-CANARY >&2;;
state) printf '{"serial":1,"lineage":"fixture"}';;
-v) printf 'Terraform v1.16.7\non fake\n';;
esac
`

type harness struct {
	dir    string
	work   string
	outdir string
	logs   bytes.Buffer
	req    models.OutRequest
	now    time.Time
	clock  func() time.Time
}

func setup(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	output := filepath.Join(dir, "output")
	bin := filepath.Join(dir, "bin")
	for _, p := range []string{work, output, bin} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := ioutil.WriteFile(filepath.Join(bin, "terraform"), []byte(fakeCLI), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_LOG", filepath.Join(dir, "calls"))
	t.Setenv("FAKE_FAIL", "")
	t.Setenv("FAKE_PLAN_BASE64", "")
	t.Setenv("FAKE_JSON_BASE64", "")
	t.Setenv("FAKE_RECORD", "")
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
	h := &harness{dir: dir, work: work, outdir: output, now: time.Date(2026, 11, 15, 20, 0, 0, 0, time.UTC), req: models.OutRequest{Source: models.Source{Terraform: models.Terraform{BackendType: "fake"}}, Params: models.OutParams{EnvName: "tools", Terraform: models.Terraform{Source: work, PlanOnly: true}, SensitivePlan: true}}}
	h.clock = func() time.Time { return h.now }
	return h
}
func (h *harness) runner() out.Runner {
	return out.Runner{SourceDir: h.work, LogWriter: &h.logs, Now: h.clock}
}
func (h *harness) deadline() string { return h.now.Add(time.Minute).Format(time.RFC3339Nano) }
func (h *harness) applied() bool {
	b, _ := ioutil.ReadFile(filepath.Join(h.dir, "calls"))
	return strings.Contains(string(b), "APPLY")
}
func (h *harness) getReq(v models.Version) models.InRequest {
	return models.InRequest{Source: h.req.Source, Version: v, Params: models.InParams{VerifiedPlan: true}}
}
func read(t *testing.T, p string) []byte {
	t.Helper()
	b, e := ioutil.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func mode(t *testing.T, p string) {
	t.Helper()
	st, e := os.Stat(p)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("unsafe mode for %s: %v %v", p, st, e)
	}
}

func TestVerifiedEndToEndSynthetic(t *testing.T) {
	h := setup(t)
	run := h.runner()
	plan, err := run.Run(h.req)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Version.IsPlan() || plan.Version.PlanChecksum != verified.DigestBytes([]byte("fixture-plan")) {
		t.Fatal("bad plan version")
	}
	inrun := resourcein.Runner{OutputDir: h.outdir, LogWriter: &h.logs}
	_, err = inrun.Run(h.getReq(plan.Version))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"plan.tfplan", "plan.json", "plan-metadata.json"} {
		mode(t, filepath.Join(h.outdir, n))
	}
	var m verified.PlanMetadata
	if err = json.Unmarshal(read(t, filepath.Join(h.outdir, "plan-metadata.json")), &m); err != nil {
		t.Fatal(err)
	}
	if m.Protocol != verified.Protocol || m.BinarySHA256 != plan.Version.PlanChecksum || m.JSONSHA256 != plan.Version.PlanJSONChecksum || m.JSONSHA256 != verified.DigestBytes(read(t, filepath.Join(h.outdir, "plan.json"))) || m.Environment != "tools" || m.TerraformVersion != "1.16.7" {
		t.Fatal("wrong verified metadata")
	}
	if string(read(t, filepath.Join(h.outdir, "plan.tfplan"))) != "fixture-plan" {
		t.Fatal("wrong binary")
	}
	apply := h.req
	apply.Params.SensitivePlan = false
	apply.Params.VerifiedPlan = true
	apply.Params.PlanOnly = false
	apply.Params.PlanRun = true
	apply.Params.ExpectedPlanChecksum = m.BinarySHA256
	apply.Params.VerificationDeadline = h.deadline()
	result, err := run.Run(apply)
	if err != nil {
		t.Fatal(err)
	}
	if !h.applied() || result.Version.AppliedPlanChecksum != m.BinarySHA256 || result.Version.VerifiedProtocol != verified.Protocol || len(result.Metadata) != 0 {
		t.Fatal("bad apply result")
	}
	resultdir := filepath.Join(h.dir, "result")
	if err = os.Mkdir(resultdir, 0700); err != nil {
		t.Fatal(err)
	}
	_, err = (resourcein.Runner{OutputDir: resultdir, LogWriter: &h.logs}).Run(models.InRequest{Version: result.Version, Params: models.InParams{VerifiedApplyResult: true}})
	if err != nil {
		t.Fatal(err)
	}
	var ar verified.ApplyResult
	p := filepath.Join(resultdir, "apply-result.json")
	mode(t, p)
	if err = json.Unmarshal(read(t, p), &ar); err != nil || ar.AppliedBinarySHA256 != m.BinarySHA256 || ar.Protocol != verified.Protocol {
		t.Fatal("bad apply receipt")
	}
	if strings.Contains(h.logs.String(), "PRIVATE-CANARY") {
		t.Fatal("sensitive output logged")
	}
}

func TestVerifiedRejectsMisuseBeforeApply(t *testing.T) {
	for _, name := range []string{"missing", "bad", "direct", "planonly", "destroy", "cleanup", "imports", "two-modes", "legacy", "backend-override"} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			r := h.req
			r.Params.SensitivePlan = false
			r.Params.VerifiedPlan = true
			r.Params.PlanOnly = false
			r.Params.PlanRun = true
			r.Params.ExpectedPlanChecksum = verified.DigestBytes([]byte("fixture-plan"))
			r.Params.VerificationDeadline = h.deadline()
			switch name {
			case "missing":
				r.Params.ExpectedPlanChecksum = ""
			case "bad":
				r.Params.ExpectedPlanChecksum = strings.Repeat("0", 64)
			case "direct":
				r.Params.PlanRun = false
			case "planonly":
				r.Params.PlanOnly = true
			case "destroy":
				r.Params.Action = "destroy"
			case "cleanup":
				r.Params.DeleteOnFailure = true
			case "imports":
				r.Params.ImportFiles = []string{"fixture"}
			case "two-modes":
				r.Params.SensitivePlan = true
			case "legacy":
				r.Source.BackendType = ""
			case "backend-override":
				r.Params.BackendType = "local"
			}
			_, err := h.runner().Run(r)
			if err == nil || err.Error() != verified.ErrInvalid.Error() || h.applied() {
				t.Fatal("unsafe request accepted")
			}
			if strings.Contains(h.logs.String(), "PRIVATE-CANARY") {
				t.Fatal("logged sensitive output")
			}
		})
	}
}

func TestDeadlineRejectedBeforeAnyTerraformCLI(t *testing.T) {
	for _, name := range []string{"missing", "malformed", "expired", "equal-now", "too-far", "offset", "fraction-zeros", "whitespace", "sensitive-plan", "direct"} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			t.Setenv("FAKE_RECORD", "1")
			r := h.req
			r.Params.SensitivePlan = false
			r.Params.VerifiedPlan = true
			r.Params.PlanOnly = false
			r.Params.PlanRun = true
			r.Params.ExpectedPlanChecksum = verified.DigestBytes([]byte("fixture-plan"))
			r.Params.VerificationDeadline = h.deadline()
			switch name {
			case "missing":
				r.Params.VerificationDeadline = ""
			case "malformed":
				r.Params.VerificationDeadline = "PRIVATE-CANARY"
			case "expired":
				r.Params.VerificationDeadline = h.now.Add(-time.Second).Format(time.RFC3339Nano)
			case "equal-now":
				r.Params.VerificationDeadline = h.now.Format(time.RFC3339Nano)
			case "too-far":
				r.Params.VerificationDeadline = h.now.Add(15*time.Minute + time.Nanosecond).Format(time.RFC3339Nano)
			case "offset":
				r.Params.VerificationDeadline = h.now.Add(time.Minute).Format("2006-01-02T15:04:05-07:00")
			case "fraction-zeros":
				r.Params.VerificationDeadline = "2026-11-15T20:01:00.100Z"
			case "whitespace":
				r.Params.VerificationDeadline += "\n"
			case "sensitive-plan":
				r = h.req
				r.Params.VerificationDeadline = h.deadline()
			case "direct":
				r.Params.VerifiedPlan = false
				r.Params.ExpectedPlanChecksum = ""
			}
			result, err := h.runner().Run(r)
			if err == nil || err.Error() != verified.ErrInvalid.Error() || result.Version.VerifiedProtocol != "" || h.applied() || strings.Contains(h.logs.String(), "PRIVATE-CANARY") {
				t.Fatal("deadline misuse was accepted or leaked")
			}
			if _, err = os.Stat(filepath.Join(h.dir, "calls")); !os.IsNotExist(err) {
				t.Fatal("deadline validation ran Terraform CLI")
			}
		})
	}
}

func TestDeadlinePresenceFromConcourseJSON(t *testing.T) {
	for _, raw := range []string{`{"verification_deadline":""}`} {
		t.Run(raw, func(t *testing.T) {
			h := setup(t)
			t.Setenv("FAKE_RECORD", "1")
			var parsed models.OutParams
			if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
				t.Fatal(err)
			}
			parsed.EnvName, parsed.Source, parsed.PlanOnly = "tools", h.work, true
			r := h.req
			r.Params = parsed
			if _, err := h.runner().Run(r); err == nil || err.Error() != verified.ErrInvalid.Error() {
				t.Fatal("explicit empty deadline ignored")
			}
			r.Params.VerifiedPlan, r.Params.PlanOnly, r.Params.PlanRun = true, false, true
			r.Params.ExpectedPlanChecksum = verified.DigestBytes([]byte("fixture-plan"))
			if _, err := h.runner().Run(r); err == nil || err.Error() != verified.ErrInvalid.Error() || h.applied() {
				t.Fatal("empty verified deadline accepted")
			}
			if _, err := os.Stat(filepath.Join(h.dir, "calls")); !os.IsNotExist(err) {
				t.Fatal("terraform CLI ran")
			}
		})
	}
	var parsed models.OutParams
	if err := json.Unmarshal([]byte(`{"terraform_source":"fixture","plan_only":true,"env_name":"tools"}`), &parsed); err != nil || parsed.HasVerificationDeadline() || parsed.Source != "fixture" || !parsed.PlanOnly || parsed.EnvName != "tools" {
		t.Fatal("default input decode changed")
	}
	h := setup(t)
	request := h.req
	request.Params.SensitivePlan, request.Params.VerifiedPlan = false, true
	request.Params.PlanOnly, request.Params.PlanRun = false, true
	request.Params.ExpectedPlanChecksum = verified.DigestBytes([]byte("fixture-plan"))
	request.Params.VerificationDeadline = h.deadline()
	b, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip models.OutRequest
	if err = json.Unmarshal(b, &roundtrip); err != nil || !roundtrip.Params.HasVerificationDeadline() {
		t.Fatal("verified input decode failed")
	}
	if _, err = h.runner().Run(roundtrip); err != nil || !h.applied() {
		t.Fatal("verified decoded input failed")
	}
}

func TestDeadlineJSONRejectsDuplicateAliasesAndInvalidTypes(t *testing.T) {
	cases := map[string]string{
		"valid then null":  `{"verification_deadline":"2026-11-15T20:01:00Z","verification_deadline":null}`,
		"null then valid":  `{"verification_deadline":null,"verification_deadline":"2026-11-15T20:01:00Z"}`,
		"duplicate valid":  `{"verification_deadline":"2026-11-15T20:01:00Z","verification_deadline":"2026-11-15T20:01:00Z"}`,
		"valid then empty": `{"verification_deadline":"2026-11-15T20:01:00Z","verification_deadline":""}`,
		"case alias":       `{"Verification_Deadline":"2026-11-15T20:01:00Z"}`,
		"mixed alias":      `{"verification_deadline":"2026-11-15T20:01:00Z","Verification_Deadline":"2026-11-15T20:01:00Z"}`,
		"null":             `{"verification_deadline":null}`,
		"number":           `{"verification_deadline":42}`,
		"object":           `{"verification_deadline":{"data":"PRIVATE-CANARY"}}`,
		"boolean":          `{"verification_deadline":false}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			t.Setenv("FAKE_RECORD", "1")
			r := h.req
			r.Params.SensitivePlan, r.Params.VerifiedPlan = false, true
			r.Params.PlanOnly, r.Params.PlanRun = false, true
			r.Params.ExpectedPlanChecksum = verified.DigestBytes([]byte("fixture-plan"))
			r.Params.VerificationDeadline = h.deadline()
			if err := json.Unmarshal([]byte(raw), &r.Params); err == nil || err.Error() != "invalid verification_deadline" {
				t.Fatal("invalid deadline JSON not rejected safely")
			}
			// Even a buggy caller ignoring the decode error cannot reuse consent.
			if r.Params.HasVerificationDeadline() || r.Params.VerificationDeadline != "" {
				t.Fatal("prior deadline survived failed decode")
			}
			if _, err := h.runner().Run(r); err == nil || err.Error() != verified.ErrInvalid.Error() || h.applied() || strings.Contains(h.logs.String(), "PRIVATE-CANARY") {
				t.Fatal("unsafe request ran")
			}
			if _, err := os.Stat(filepath.Join(h.dir, "calls")); !os.IsNotExist(err) {
				t.Fatal("Terraform CLI ran")
			}
		})
	}
}

func TestDeadlineJSONReuseResetsOnlyDeadline(t *testing.T) {
	h := setup(t)
	t.Setenv("FAKE_RECORD", "1")
	r := h.req
	r.Params.SensitivePlan, r.Params.VerifiedPlan = false, true
	r.Params.PlanOnly, r.Params.PlanRun = false, true
	r.Params.ExpectedPlanChecksum = verified.DigestBytes([]byte("fixture-plan"))
	if err := json.Unmarshal([]byte(`{"verification_deadline":"2026-11-15T20:01:00Z"}`), &r.Params); err != nil || !r.Params.HasVerificationDeadline() {
		t.Fatal("valid deadline decode failed")
	}
	// Duplicates of legacy fields retain the old last-value-wins behavior;
	// a same-named nested variable is unrelated to the new top-level field.
	if err := json.Unmarshal([]byte(`{"env_name":"old","env_name":"tools","env":{"verification_deadline":"nested"}}`), &r.Params); err != nil {
		t.Fatal(err)
	}
	if r.Params.HasVerificationDeadline() || r.Params.VerificationDeadline != "" || r.Params.EnvName != "tools" || r.Params.Env["verification_deadline"] != "nested" || !r.Params.VerifiedPlan || !r.Params.PlanRun {
		t.Fatal("reused decode retained deadline or changed legacy fields")
	}
	if _, err := h.runner().Run(r); err == nil || err.Error() != verified.ErrInvalid.Error() || h.applied() {
		t.Fatal("stale reused deadline authorized apply")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "calls")); !os.IsNotExist(err) {
		t.Fatal("Terraform CLI ran")
	}
}

func TestDeadlineExpiresDuringPreparation(t *testing.T) {
	for _, phase := range []string{"init", "output"} {
		t.Run(phase, func(t *testing.T) {
			h := setup(t)
			t.Setenv("FAKE_RECORD", "1")
			h.clock = func() time.Time {
				calls, _ := ioutil.ReadFile(filepath.Join(h.dir, "calls"))
				if strings.Contains(string(calls), "CALL:"+phase+"\n") {
					return h.now.Add(2 * time.Minute)
				}
				return h.now
			}
			r := h.req
			r.Params.SensitivePlan, r.Params.VerifiedPlan = false, true
			r.Params.PlanOnly, r.Params.PlanRun = false, true
			r.Params.ExpectedPlanChecksum = verified.DigestBytes([]byte("fixture-plan"))
			r.Params.VerificationDeadline = h.deadline()
			result, err := h.runner().Run(r)
			calls, _ := ioutil.ReadFile(filepath.Join(h.dir, "calls"))
			if err == nil || err.Error() != verified.ErrInvalid.Error() || result.Version.VerifiedProtocol != "" || h.applied() || strings.Contains(string(calls), "CALL:apply\n") || !strings.Contains(string(calls), "CALL:"+phase+"\n") || strings.Contains(h.logs.String(), "PRIVATE-CANARY") {
				t.Fatal("expired preparation applied or leaked")
			}
		})
	}
}

func TestDeadlineCanonicalBoundaries(t *testing.T) {
	base := time.Date(2026, 11, 15, 20, 0, 0, 0, time.UTC)
	for _, duration := range []time.Duration{time.Nanosecond, 10 * time.Millisecond, time.Second, 15 * time.Minute} {
		encoded := base.Add(duration).Format(time.RFC3339Nano)
		got, err := verified.ParseDeadline(encoded, base)
		if err != nil || !got.Equal(base.Add(duration)) {
			t.Fatal("valid canonical deadline rejected")
		}
	}
	if _, err := verified.ParseDeadline(base.Add(15*time.Minute+time.Nanosecond).Format(time.RFC3339Nano), base); err == nil {
		t.Fatal("unbounded deadline accepted")
	}
}

func TestVerifiedGetRejectsMissingStaleAndSuppressesErrors(t *testing.T) {
	for _, name := range []string{"missing", "missing-protocol", "stale", "wrongversion", "json-tamper", "json-mismatch", "init-failure", "backend-override"} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			version := models.Version{EnvName: "tools", PlanOnly: "true", PlanChecksum: verified.DigestBytes([]byte("fixture-plan")), PlanJSONChecksum: verified.DigestBytes([]byte("{\"synthetic\":\"PRIVATE-CANARY\"}\n")), VerifiedProtocol: verified.Protocol}
			switch name {
			case "missing":
				version.PlanChecksum = ""
			case "missing-protocol":
				version.VerifiedProtocol = ""
			case "stale":
				t.Setenv("FAKE_PLAN_BASE64", "b3RoZXI=")
			case "wrongversion":
				version.PlanOnly = ""
			case "json-tamper":
				t.Setenv("FAKE_JSON_BASE64", "ZmFrZQ==")
			case "json-mismatch":
				version.PlanJSONChecksum = strings.Repeat("0", 64)
			case "init-failure":
				t.Setenv("FAKE_FAIL", "init")
			}
			req := h.getReq(version)
			if name == "backend-override" {
				req.Params.BackendType = "local"
			}
			_, err := (resourcein.Runner{OutputDir: h.outdir, LogWriter: &h.logs}).Run(req)
			if err == nil || err.Error() != verified.ErrInvalid.Error() {
				t.Fatal("invalid plan accepted")
			}
			if strings.Contains(h.logs.String(), "PRIVATE-CANARY") {
				t.Fatal("logged sensitive output")
			}
			for _, n := range []string{"plan.tfplan", "plan.json", "plan-metadata.json"} {
				if _, err := os.Stat(filepath.Join(h.outdir, n)); !os.IsNotExist(err) {
					t.Fatal("partial artifact")
				}
			}
		})
	}
}

func TestStrictCLIFailuresAreRedacted(t *testing.T) {
	for _, failure := range []string{"plan", "show", "apply"} {
		t.Run(failure, func(t *testing.T) {
			h := setup(t)
			t.Setenv("FAKE_FAIL", failure)
			_, err := h.runner().Run(h.req)
			if err == nil || err.Error() != verified.ErrInvalid.Error() || strings.Contains(h.logs.String(), "PRIVATE-CANARY") {
				t.Fatal("sensitive failure leaked or succeeded")
			}
		})
	}
}

func TestStrictApplyFailureIsRedactedAndHasNoReceipt(t *testing.T) {
	h := setup(t)
	r := h.req
	r.Params.SensitivePlan = false
	r.Params.VerifiedPlan = true
	r.Params.PlanOnly = false
	r.Params.PlanRun = true
	r.Params.ExpectedPlanChecksum = verified.DigestBytes([]byte("fixture-plan"))
	r.Params.VerificationDeadline = h.deadline()
	t.Setenv("FAKE_FAIL", "apply")
	result, err := h.runner().Run(r)
	if err == nil || err.Error() != verified.ErrInvalid.Error() || result.Version.VerifiedProtocol != "" || strings.Contains(h.logs.String(), "PRIVATE-CANARY") {
		t.Fatal("failed apply emitted receipt or leaked output")
	}
}

func TestStrictScrubsInheritedAndModelEnvironment(t *testing.T) {
	h := setup(t)
	t.Setenv("TF_LOG", "DEBUG")
	t.Setenv("TF_LOG_PATH", filepath.Join(h.dir, "raw-log"))
	t.Setenv("TF_CLI_ARGS_plan", "-destroy")
	t.Setenv("TF_WORKSPACE", "wrong")
	t.Setenv("TF_REATTACH_PROVIDERS", "synthetic")
	h.req.Source.Terraform.Env = map[string]string{"TF_LOG_PROVIDER": "TRACE", "TF_CLI_ARGS": "-destroy", "TF_WORKSPACE": "wrong"}
	plan, err := h.runner().Run(h.req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (resourcein.Runner{OutputDir: h.outdir}).Run(h.getReq(plan.Version)); err != nil {
		t.Fatal(err)
	}
	r := h.req
	r.Params.SensitivePlan = false
	r.Params.VerifiedPlan = true
	r.Params.PlanOnly = false
	r.Params.PlanRun = true
	r.Params.ExpectedPlanChecksum = plan.Version.PlanChecksum
	r.Params.VerificationDeadline = h.deadline()
	if _, err = h.runner().Run(r); err != nil {
		t.Fatal(err)
	}
	b, _ := ioutil.ReadFile(filepath.Join(h.dir, "calls"))
	if strings.Contains(string(b), "ENV-LEAK") || strings.Contains(string(b), "WORKSPACE-LEAK") {
		t.Fatal("strict terraform env leaked unsafe variables")
	}
	if _, err = os.Stat(filepath.Join(h.dir, "raw-log")); !os.IsNotExist(err) {
		t.Fatal("raw log created")
	}
}

func TestApplyReceiptCapability(t *testing.T) {
	h := setup(t)
	sum := verified.DigestBytes([]byte("fixture-plan"))
	r := h.req
	r.Params.SensitivePlan = false
	r.Params.VerifiedPlan = true
	r.Params.PlanOnly = false
	r.Params.PlanRun = true
	r.Params.ExpectedPlanChecksum = sum
	r.Params.VerificationDeadline = h.deadline()
	resp, err := h.runner().Run(r)
	if err != nil || resp.Version.AppliedPlanChecksum != sum || !h.applied() {
		t.Fatal("checksum apply failed")
	}
	outdir := filepath.Join(h.dir, "receipt")
	if err := os.Mkdir(outdir, 0700); err != nil {
		t.Fatal(err)
	}
	v := resp.Version
	v.VerifiedProtocol = ""
	if _, err = (resourcein.Runner{OutputDir: outdir}).Run(models.InRequest{Version: v, Params: models.InParams{VerifiedApplyResult: true}}); err == nil {
		t.Fatal("missing capability accepted")
	}
	if _, err = os.Stat(filepath.Join(outdir, "apply-result.json")); !os.IsNotExist(err) {
		t.Fatal("unverified receipt")
	}
}

func TestDefaultPlanOutputRemainsUnchanged(t *testing.T) {
	h := setup(t)
	t.Setenv("TF_LOG", "DEBUG")
	h.req.Params.SensitivePlan = false
	_, err := h.runner().Run(h.req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.logs.String(), "PRIVATE-CANARY") {
		t.Fatal("default output was suppressed")
	}
	calls, _ := ioutil.ReadFile(filepath.Join(h.dir, "calls"))
	if !strings.Contains(string(calls), "ENV-LEAK") {
		t.Fatal("default environment changed")
	}
}
