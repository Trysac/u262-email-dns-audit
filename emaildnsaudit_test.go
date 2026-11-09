package emaildnsaudit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

// fakeResolver implements Resolver with a map of TXT records.
type fakeResolver struct {
	records      map[string][]string
	lookupErrors map[string]error
	err          error
}

func (f *fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if f.lookupErrors != nil {
		if err, ok := f.lookupErrors[name]; ok {
			return nil, err
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	records, ok := f.records[name]
	if !ok {
		return nil, &net.DNSError{IsNotFound: true}
	}
	return records, nil
}

func newFakeResolver(records map[string][]string) *fakeResolver {
	return &fakeResolver{records: records}
}

func setResolverForTest(r Resolver) {
	resolverForTests = r
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "valid domain", input: "example.com", want: "example.com"},
		{name: "trailing dot removed", input: "example.com.", want: "example.com"},
		{name: "valid with hyphen", input: "my-domain.com", want: "my-domain.com"},
		{name: "empty", input: "", wantErr: true},
		{name: "too long", input: strings.Repeat("a", 254), wantErr: true},
		{name: "label too long", input: strings.Repeat("a", 64) + ".com", wantErr: true},
		{name: "label starts with hyphen", input: "-a.com", wantErr: true},
		{name: "label ends with hyphen", input: "a-.com", wantErr: true},
		{name: "invalid character", input: "a_b.com", wantErr: true},
		{name: "double dot", input: "a..com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeDomain(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeDomain(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAuditNoRecords(t *testing.T) {
	resolver := newFakeResolver(map[string][]string{})
	setResolverForTest(resolver)
	report, err := Audit(context.Background(), "example.com", Options{})
	if err != nil {
		t.Fatalf("Audit returned error: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings (SPF001, DMARC001), got %d: %+v", len(report.Findings), report.Findings)
	}
}

func TestAuditSPF(t *testing.T) {
	tests := []struct {
		name         string
		records      map[string][]string
		expectCode   string
		expectSev    string
		expectMsg    string
		expectNoCode string
	}{
		{
			name:       "no SPF",
			records:    map[string][]string{},
			expectCode: "SPF001",
			expectSev:  "high",
		},
		{
			name: "multiple SPF",
			records: map[string][]string{
				"example.com": {"v=spf1 -all", "v=spf1 +all"},
			},
			expectCode: "SPF002",
			expectSev:  "high",
		},
		{
			name: "+all",
			records: map[string][]string{
				"example.com": {"v=spf1 +all"},
			},
			expectCode: "SPF003",
			expectSev:  "high",
		},
		{
			name: "bare all",
			records: map[string][]string{
				"example.com": {"v=spf1 all"},
			},
			expectCode: "SPF003",
			expectSev:  "high",
		},
		{
			name: "?all",
			records: map[string][]string{
				"example.com": {"v=spf1 ?all"},
			},
			expectCode: "SPF004",
			expectSev:  "medium",
		},
		{
			name: "no all no redirect",
			records: map[string][]string{
				"example.com": {"v=spf1 mx"},
			},
			expectCode: "SPF004",
			expectSev:  "medium",
		},
		{
			name: "redirect no all",
			records: map[string][]string{
				"example.com":      {"v=spf1 redirect=_spf.example.com"},
				"_spf.example.com": {"v=spf1 -all"},
			},
			expectNoCode: "SPF004",
		},
		{
			name: "ptr",
			records: map[string][]string{
				"example.com": {"v=spf1 ptr -all"},
			},
			expectCode: "SPF006",
			expectSev:  "low",
		},
		{
			name: "unknown mechanism",
			records: map[string][]string{
				"example.com": {"v=spf1 bogus -all"},
			},
			expectCode: "SPF002",
			expectSev:  "high",
		},
		{
			name: "include target missing",
			records: map[string][]string{
				"example.com": {"v=spf1 include:_spf.example.com -all"},
			},
			expectCode: "SPF002",
			expectSev:  "high",
		},
		{
			name: "include target multiple",
			records: map[string][]string{
				"example.com":      {"v=spf1 include:_spf.example.com -all"},
				"_spf.example.com": {"v=spf1 -all", "v=spf1 +all"},
			},
			expectCode: "SPF002",
			expectSev:  "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := newFakeResolver(tt.records)
			setResolverForTest(resolver)
			report, err := Audit(context.Background(), "example.com", Options{})
			if err != nil {
				t.Fatalf("Audit error: %v", err)
			}
			if tt.expectNoCode != "" {
				if hasFinding(&report, tt.expectNoCode) {
					t.Errorf("did not expect finding %s, got: %+v", tt.expectNoCode, report.Findings)
				}
				return
			}
			if !hasFinding(&report, tt.expectCode) {
				t.Errorf("expected finding %s, got: %+v", tt.expectCode, report.Findings)
				return
			}
			for _, f := range report.Findings {
				if f.Code == tt.expectCode {
					if f.Severity != tt.expectSev {
						t.Errorf("severity = %s, want %s", f.Severity, tt.expectSev)
					}
					if tt.expectMsg != "" && f.Message != tt.expectMsg {
						t.Errorf("message = %q, want %q", f.Message, tt.expectMsg)
					}
				}
			}
		})
	}
}

func TestAuditSPFLookupLimit(t *testing.T) {
	// chain: example.com includes a1, a1 includes a2, ... up to a10 includes a11?
	// We'll create 11 includes, causing 11 lookups.
	records := map[string][]string{}
	for i := 0; i < 11; i++ {
		domain := fmt.Sprintf("a%d.example", i)
		if i < 10 {
			records[domain] = []string{fmt.Sprintf("v=spf1 include:a%d.example -all", i+1)}
		} else {
			records[domain] = []string{"v=spf1 -all"}
		}
	}
	records["example.com"] = []string{"v=spf1 include:a0.example -all"}
	resolver := newFakeResolver(records)
	setResolverForTest(resolver)
	report, err := Audit(context.Background(), "example.com", Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	if report.SPFLookups != 11 {
		t.Errorf("SPFLookups = %d, want 11", report.SPFLookups)
	}
	if !hasFinding(&report, "SPF005") {
		t.Errorf("expected SPF005, got: %+v", report.Findings)
	}
	// loop: a -> b -> a
	records2 := map[string][]string{
		"a.example": {"v=spf1 include:b.example -all"},
		"b.example": {"v=spf1 include:a.example -all"},
	}
	resolver2 := newFakeResolver(records2)
	setResolverForTest(resolver2)
	report2, err := Audit(context.Background(), "a.example", Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	if !hasFinding(&report2, "SPF005") {
		t.Errorf("expected SPF005 for loop, got: %+v", report2.Findings)
	}
}

func TestAuditSPFLookupLimitMessage(t *testing.T) {
	// example.com includes a1, each aN includes a(N+1) up to a11: 11 include terms.
	records := map[string][]string{
		"example.com": {"v=spf1 include:a1.example -all"},
	}
	for i := 1; i <= 10; i++ {
		records[fmt.Sprintf("a%d.example", i)] = []string{fmt.Sprintf("v=spf1 include:a%d.example -all", i+1)}
	}
	records["a11.example"] = []string{"v=spf1 -all"}

	resolver := newFakeResolver(records)
	setResolverForTest(resolver)
	report, err := Audit(context.Background(), "example.com", Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	if report.SPFLookups != 11 {
		t.Errorf("SPFLookups = %d, want 11", report.SPFLookups)
	}
	found := false
	for _, f := range report.Findings {
		if f.Code == "SPF005" {
			found = true
			if f.Severity != "high" {
				t.Errorf("SPF005 severity = %s, want high", f.Severity)
			}
			if f.Message != "SPF needs 11 DNS lookups, the limit is 10" {
				t.Errorf("SPF005 message = %q, want %q", f.Message, "SPF needs 11 DNS lookups, the limit is 10")
			}
		}
	}
	if !found {
		t.Errorf("expected SPF005, got: %+v", report.Findings)
	}
}

func TestAuditSPFRedirectNoAll(t *testing.T) {
	resolver := newFakeResolver(map[string][]string{
		"example.com":      {"v=spf1 redirect=_spf.example.net"},
		"_spf.example.net": {"v=spf1 -all"},
	})
	setResolverForTest(resolver)
	report, err := Audit(context.Background(), "example.com", Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	if hasFinding(&report, "SPF004") {
		t.Errorf("did not expect SPF004 for redirect-only record, got: %+v", report.Findings)
	}
}

func TestAuditSPF10IsNotSPF(t *testing.T) {
	resolver := newFakeResolver(map[string][]string{
		"example.com": {"v=spf10 -all"},
	})
	setResolverForTest(resolver)
	report, err := Audit(context.Background(), "example.com", Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	if !hasFinding(&report, "SPF001") {
		t.Errorf("expected SPF001 when the only record is v=spf10 -all, got: %+v", report.Findings)
	}
}

func TestAuditDMARC(t *testing.T) {
	tests := []struct {
		name            string
		records         map[string][]string
		expectCode      string
		expectSev       string
		expectNoFinding bool
	}{
		{
			name: "no DMARC",
			records: map[string][]string{
				"example.com": {"v=spf1 -all"},
			},
			expectCode: "DMARC001",
			expectSev:  "high",
		},
		{
			name: "p none",
			records: map[string][]string{
				"example.com":        {"v=spf1 -all"},
				"_dmarc.example.com": {"v=DMARC1; p=none"},
			},
			expectCode: "DMARC002",
			expectSev:  "medium",
		},
		{
			name: "v not first",
			records: map[string][]string{
				"example.com":        {"v=spf1 -all"},
				"_dmarc.example.com": {"p=reject; v=DMARC1"},
			},
			expectCode: "DMARC003",
			expectSev:  "high",
		},
		{
			name: "missing p",
			records: map[string][]string{
				"example.com":        {"v=spf1 -all"},
				"_dmarc.example.com": {"v=DMARC1; rua=mailto:test@example.com"},
			},
			expectCode: "DMARC003",
			expectSev:  "high",
		},
		{
			name: "invalid p",
			records: map[string][]string{
				"example.com":        {"v=spf1 -all"},
				"_dmarc.example.com": {"v=DMARC1; p=maybe"},
			},
			expectCode: "DMARC003",
			expectSev:  "high",
		},
		{
			name: "multiple DMARC",
			records: map[string][]string{
				"example.com":        {"v=spf1 -all"},
				"_dmarc.example.com": {"v=DMARC1; p=none", "v=DMARC1; p=reject"},
			},
			expectCode: "DMARC003",
			expectSev:  "high",
		},
		{
			name: "uppercase V tag is valid",
			records: map[string][]string{
				"example.com":        {"v=spf1 -all"},
				"_dmarc.example.com": {"V=DMARC1; p=reject"},
			},
			expectNoFinding: true,
		},
		{
			name: "lowercase DMARC1 value is not a record",
			records: map[string][]string{
				"example.com":        {"v=spf1 -all"},
				"_dmarc.example.com": {"v=dmarc1; p=reject"},
			},
			expectCode: "DMARC001",
			expectSev:  "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := newFakeResolver(tt.records)
			setResolverForTest(resolver)
			report, err := Audit(context.Background(), "example.com", Options{})
			if err != nil {
				t.Fatalf("Audit error: %v", err)
			}
			if tt.expectNoFinding {
				if len(report.Findings) != 0 {
					t.Errorf("expected no findings, got: %+v", report.Findings)
				}
				return
			}
			if !hasFinding(&report, tt.expectCode) {
				t.Errorf("expected %s, got: %+v", tt.expectCode, report.Findings)
				return
			}
			for _, f := range report.Findings {
				if f.Code == tt.expectCode {
					if f.Severity != tt.expectSev {
						t.Errorf("severity = %s, want %s", f.Severity, tt.expectSev)
					}
				}
			}
		})
	}
}

func TestAuditDKIM(t *testing.T) {
	tests := []struct {
		name             string
		records          map[string][]string
		selectors        []string
		expectMsg        string
		expectNoFindings bool
	}{
		{
			name: "missing selector",
			records: map[string][]string{
				"example.com": {"v=spf1 -all"},
			},
			selectors: []string{"s1"},
			expectMsg: "DKIM selector s1 has no record",
		},
		{
			name: "empty p",
			records: map[string][]string{
				"example.com":               {"v=spf1 -all"},
				"s1._domainkey.example.com": {"v=DKIM1; p="},
			},
			selectors: []string{"s1"},
			expectMsg: "DKIM selector s1 is revoked (empty p=)",
		},
		{
			name: "valid p",
			records: map[string][]string{
				"example.com":               {"v=spf1 -all"},
				"_dmarc.example.com":        {"v=DMARC1; p=reject"},
				"s1._domainkey.example.com": {"v=DKIM1; p=MIIBIjANBg"},
			},
			selectors:        []string{"s1"},
			expectNoFindings: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := newFakeResolver(tt.records)
			setResolverForTest(resolver)
			report, err := Audit(context.Background(), "example.com", Options{DKIMSelectors: tt.selectors})
			if err != nil {
				t.Fatalf("Audit error: %v", err)
			}
			if tt.expectNoFindings {
				if len(report.Findings) != 0 {
					t.Errorf("expected no findings, got: %+v", report.Findings)
				}
				return
			}
			found := false
			for _, f := range report.Findings {
				if f.Code == "DKIM001" && f.Message == tt.expectMsg {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected DKIM001 with %q, got: %+v", tt.expectMsg, report.Findings)
			}
		})
	}
}

func TestAuditResolverError(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("network error")}
	setResolverForTest(resolver)
	_, err := Audit(context.Background(), "example.com", Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrLookup) {
		t.Errorf("error should wrap ErrLookup, got: %v", err)
	}
}

func TestAuditSPFIncludeResolverError(t *testing.T) {
	resolver := &fakeResolver{
		records: map[string][]string{
			"example.com": {"v=spf1 include:_spf.example.net -all"},
		},
		lookupErrors: map[string]error{
			"_spf.example.net": &net.DNSError{IsNotFound: false},
		},
	}
	setResolverForTest(resolver)
	report, err := Audit(context.Background(), "example.com", Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrLookup) {
		t.Errorf("error should wrap ErrLookup, got: %v", err)
	}
	if hasFinding(&report, "SPF002") {
		t.Errorf("did not expect SPF002 for a resolver error, got: %+v", report.Findings)
	}
}

func TestAuditInvalidDomain(t *testing.T) {
	resolver := newFakeResolver(nil)
	setResolverForTest(resolver)
	_, err := Audit(context.Background(), "exa mple.com", Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("error should wrap ErrInvalidDomain, got: %v", err)
	}
}

func TestRun(t *testing.T) {
	oldResolver := resolverForTests
	defer func() { resolverForTests = oldResolver }()
	resolver := newFakeResolver(map[string][]string{
		"example.com":        {"v=spf1 -all"},
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	})

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "no args",
			args:       []string{},
			wantCode:   2,
			wantStderr: "usage",
		},
		{
			name:       "json no high finding",
			args:       []string{"--json", "example.com"},
			wantCode:   0,
			wantStdout: `"domain"`,
		},
		{
			name:     "with dkim selectors",
			args:     []string{"--dkim", "s1,s2", "example.com"},
			wantCode: 0,
		},
	}

	resolverForTests = resolver
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			code := Run(tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("Run(%v) = %d, want %d", tt.args, code, tt.wantCode)
			}
			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}

	// A high finding makes the JSON run exit with 1.
	resolverForTests = newFakeResolver(map[string][]string{
		"example.com": {"v=spf1 +all"},
	})
	if code := Run([]string{"--json", "example.com"}, io.Discard, io.Discard); code != 1 {
		t.Errorf("expected 1 for high finding, got %d", code)
	}
}

func ExampleAudit() {
	// Set up fake resolver for demonstration.
	resolverForTests = newFakeResolver(map[string][]string{
		"example.com":               {"v=spf1 include:_spf.example.net -all"},
		"_spf.example.net":          {"v=spf1 ip4:192.0.2.0/24 -all"},
		"_dmarc.example.com":        {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
		"s1._domainkey.example.com": {"v=DKIM1; k=rsa; p=MIIBIjANBg"},
	})
	report, _ := Audit(context.Background(), "example.com", Options{DKIMSelectors: []string{"s1"}})
	fmt.Printf("Domain: %s, SPFLookups: %d, Findings: %d\n", report.Domain, report.SPFLookups, len(report.Findings))
	// Output:
	// Domain: example.com, SPFLookups: 1, Findings: 0
}
