package emaildnsaudit

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

// Resolver is the interface for DNS TXT lookups. It matches *net.Resolver's LookupTXT method.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Options configures the audit.
type Options struct {
	// Resolver is used for DNS lookups. If nil, net.DefaultResolver is used.
	Resolver Resolver
	// DKIMSelectors lists DKIM selectors to check. Empty means no DKIM checks.
	DKIMSelectors []string
	// Timeout is applied per lookup. If zero, 5 seconds is used.
	Timeout time.Duration
}

// Finding represents a single audit finding.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Report contains the audit results.
type Report struct {
	Domain     string    `json:"domain"`
	SPF        string    `json:"spf"`
	DMARC      string    `json:"dmarc"`
	SPFLookups int       `json:"spf_lookups"`
	Findings   []Finding `json:"findings"`
}

var (
	ErrInvalidDomain = errors.New("emaildnsaudit: invalid domain")
	ErrLookup        = errors.New("emaildnsaudit: DNS lookup failed")
)

// resolverForTests allows tests to inject a fake resolver.
var resolverForTests Resolver

// Audit checks the domain's SPF, DMARC, and DKIM records.
func Audit(ctx context.Context, domain string, opts Options) (Report, error) {
	domain, err := normalizeDomain(domain)
	if err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrInvalidDomain, err)
	}
	if opts.Resolver == nil {
		if resolverForTests != nil {
			opts.Resolver = resolverForTests
		} else {
			opts.Resolver = net.DefaultResolver
		}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	report := Report{Domain: domain}

	// SPF
	spfRecords, err := lookupSPF(ctx, domain, opts)
	if err != nil {
		if !isNotFound(err) {
			return report, fmt.Errorf("%w: %v", ErrLookup, err)
		}
		spfRecords = nil
	}
	if len(spfRecords) == 0 {
		report.Findings = append(report.Findings, Finding{Code: "SPF001", Severity: "high", Message: "no SPF record"})
	} else if len(spfRecords) > 1 {
		report.Findings = append(report.Findings, Finding{Code: "SPF002", Severity: "high", Message: "multiple SPF records"})
		report.SPF = strings.Join(spfRecords, " ")
	} else {
		report.SPF = spfRecords[0]
		lookupCount := 0
		evalErr := evalSPF(ctx, domain, spfRecords[0], opts, &report, &lookupCount)
		report.SPFLookups = lookupCount
		if evalErr != nil {
			return report, evalErr
		}
	}

	// DMARC
	dmarcRecords, err := lookupTXT(ctx, "_dmarc."+domain, opts)
	if err != nil {
		if isNotFound(err) {
			report.Findings = append(report.Findings, Finding{Code: "DMARC001", Severity: "high", Message: "no DMARC record"})
		} else {
			return report, fmt.Errorf("%w: %v", ErrLookup, err)
		}
	} else {
		var validDMARC []string
		for _, r := range dmarcRecords {
			if isDMARCRecord(r) {
				validDMARC = append(validDMARC, r)
			}
		}
		if len(validDMARC) == 0 {
			report.Findings = append(report.Findings, Finding{Code: "DMARC001", Severity: "high", Message: "no DMARC record"})
		} else if len(validDMARC) > 1 {
			report.Findings = append(report.Findings, Finding{Code: "DMARC003", Severity: "high", Message: "multiple DMARC records"})
		} else {
			report.DMARC = validDMARC[0]
			parseDMARC(validDMARC[0], &report)
		}
	}

	// DKIM
	for _, selector := range opts.DKIMSelectors {
		dkimRecords, err := lookupTXT(ctx, selector+"._domainkey."+domain, opts)
		if err != nil {
			if isNotFound(err) {
				report.Findings = append(report.Findings, Finding{
					Code: "DKIM001", Severity: "medium",
					Message: fmt.Sprintf("DKIM selector %s has no record", selector),
				})
			} else {
				return report, fmt.Errorf("%w: %v", ErrLookup, err)
			}
		} else {
			for _, r := range dkimRecords {
				if hasEmptyP(r) {
					report.Findings = append(report.Findings, Finding{
						Code: "DKIM001", Severity: "medium",
						Message: fmt.Sprintf("DKIM selector %s is revoked (empty p=)", selector),
					})
					break
				}
			}
		}
	}

	sortFindings(&report)
	return report, nil
}

// normalizeDomain validates and normalizes the domain: removes trailing dot, checks length, labels.
func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSuffix(domain, ".")
	if len(domain) == 0 || len(domain) > 253 {
		return "", errors.New("domain length must be 1-253 characters")
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", errors.New("label length must be 1-63 characters")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("label cannot start or end with hyphen")
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return "", errors.New("label contains invalid character")
			}
		}
	}
	return domain, nil
}

// lookupTXT performs a TXT lookup with timeout.
func lookupTXT(ctx context.Context, name string, opts Options) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	records, err := opts.Resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, err
	}
	// filter out records >4096 bytes
	var valid []string
	for _, r := range records {
		if len(r) <= 4096 {
			valid = append(valid, r)
		}
	}
	return valid, nil
}

// lookupSPF returns TXT records that are SPF records (starting with v=spf1 followed by space or end).
func lookupSPF(ctx context.Context, domain string, opts Options) ([]string, error) {
	records, err := lookupTXT(ctx, domain, opts)
	if err != nil {
		return nil, err
	}
	var spfRecords []string
	for _, r := range records {
		if strings.HasPrefix(r, "v=spf1") && (len(r) == len("v=spf1") || r[len("v=spf1")] == ' ') {
			spfRecords = append(spfRecords, r)
		}
	}
	return spfRecords, nil
}

// evalSPF evaluates a single SPF record's terms, updating report and lookupCount. It recursively processes includes and redirects and returns a wrapped ErrLookup when a target lookup fails for a reason other than not-found.
func evalSPF(ctx context.Context, domain, spf string, opts Options, report *Report, lookupCount *int) error {
	if *lookupCount > 10 {
		// already exceeded, ensure SPF005 is present
		ensureSPF005(report, *lookupCount)
		return nil
	}
	terms := strings.Fields(spf)
	hasAll := false
	hasQuestionAll := false
	hasRedirect := false
	hasPtr := false

	for _, term := range terms {
		if *lookupCount > 10 {
			ensureSPF005(report, *lookupCount)
			return nil
		}
		// Modifier?
		if idx := strings.Index(term, "="); idx >= 0 {
			modName := term[:idx]
			modVal := term[idx+1:]
			if strings.EqualFold(modName, "redirect") {
				hasRedirect = true
				*lookupCount++
				if *lookupCount > 10 {
					ensureSPF005(report, *lookupCount)
					return nil
				}
				targetRecords, err := lookupSPF(ctx, modVal, opts)
				if err != nil {
					if !isNotFound(err) {
						return fmt.Errorf("%w: %v", ErrLookup, err)
					}
					addSPF002(report, "redirect target does not have exactly one SPF record")
					return nil
				}
				if len(targetRecords) != 1 {
					addSPF002(report, "redirect target does not have exactly one SPF record")
					return nil
				}
				if err := evalSPF(ctx, modVal, targetRecords[0], opts, report, lookupCount); err != nil {
					return err
				}
			}
			// other modifiers ignored
			continue
		}
		// Mechanism
		qualifier := byte('+')
		mechanism := term
		if len(term) > 0 && strings.ContainsRune("+-~?", rune(term[0])) {
			qualifier = term[0]
			mechanism = term[1:]
		}
		mechName := mechanism
		arg := ""
		if idx := strings.Index(mechanism, ":"); idx >= 0 {
			mechName = mechanism[:idx]
			arg = mechanism[idx+1:]
		}
		lowerMech := strings.ToLower(mechName)
		switch lowerMech {
		case "all":
			hasAll = true
			if qualifier == '+' {
				addSPF003(report)
			} else if qualifier == '?' {
				hasQuestionAll = true
			}
		case "include":
			*lookupCount++
			if *lookupCount > 10 {
				ensureSPF005(report, *lookupCount)
				return nil
			}
			if arg == "" {
				addSPF002(report, "include without domain")
				return nil
			}
			targetRecords, err := lookupSPF(ctx, arg, opts)
			if err != nil {
				if !isNotFound(err) {
					return fmt.Errorf("%w: %v", ErrLookup, err)
				}
				addSPF002(report, "include target does not have exactly one SPF record")
				return nil
			}
			if len(targetRecords) != 1 {
				addSPF002(report, "include target does not have exactly one SPF record")
				return nil
			}
			if err := evalSPF(ctx, arg, targetRecords[0], opts, report, lookupCount); err != nil {
				return err
			}
		case "a", "mx", "ptr", "exists":
			*lookupCount++
			if *lookupCount > 10 {
				ensureSPF005(report, *lookupCount)
				return nil
			}
			if lowerMech == "ptr" {
				hasPtr = true
			}
		case "ip4", "ip6":
			// not counted
		default:
			addSPF002(report, fmt.Sprintf("unknown mechanism: %s", term))
			return nil
		}
	}
	// After loop, check SPF004 and SPF006 if not already added
	if !hasAll && !hasRedirect {
		addSPF004(report)
	} else if hasQuestionAll {
		addSPF004(report)
	}
	if hasPtr {
		addSPF006(report)
	}
	return nil
}

// helper functions to add findings without duplicates
func addSPF002(report *Report, msg string) {
	if !hasFinding(report, "SPF002") {
		report.Findings = append(report.Findings, Finding{Code: "SPF002", Severity: "high", Message: msg})
	}
}
func addSPF003(report *Report) {
	if !hasFinding(report, "SPF003") {
		report.Findings = append(report.Findings, Finding{Code: "SPF003", Severity: "high", Message: "SPF policy allows all (+all)"})
	}
}
func addSPF004(report *Report) {
	if !hasFinding(report, "SPF004") {
		report.Findings = append(report.Findings, Finding{Code: "SPF004", Severity: "medium", Message: "SPF policy is softfail or has no explicit all"})
	}
}
func addSPF005(report *Report, count int) {
	// too many lookups
	if !hasFinding(report, "SPF005") {
		report.Findings = append(report.Findings, Finding{Code: "SPF005", Severity: "high", Message: fmt.Sprintf("SPF needs %d DNS lookups, the limit is 10", count)})
	}
}
func ensureSPF005(report *Report, count int) {
	addSPF005(report, count)
}
func addSPF006(report *Report) {
	if !hasFinding(report, "SPF006") {
		report.Findings = append(report.Findings, Finding{Code: "SPF006", Severity: "low", Message: "SPF uses ptr mechanism (not recommended)"})
	}
}

func hasFinding(report *Report, code string) bool {
	for _, f := range report.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// isDMARCVTag reports whether tag is a DMARC version tag. Tag names are
// case-insensitive (RFC 7489 section 6.3) while the version value must be
// exactly "DMARC1".
func isDMARCVTag(tag string) bool {
	kv := strings.SplitN(strings.TrimSpace(tag), "=", 2)
	if len(kv) != 2 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(kv[0]), "v") && strings.TrimSpace(kv[1]) == "DMARC1"
}

// isDMARCRecord reports whether the TXT record contains a DMARC version tag in any position.
func isDMARCRecord(record string) bool {
	for _, tag := range strings.Split(record, ";") {
		if isDMARCVTag(tag) {
			return true
		}
	}
	return false
}

// parseDMARC parses a single DMARC record and adds findings.
func parseDMARC(record string, report *Report) {
	tags := strings.Split(record, ";")
	// first tag must be the v=DMARC1 tag
	if len(tags) < 1 || !isDMARCVTag(tags[0]) {
		addDMARC003(report, "v tag is not first")
		return
	}
	pValue := ""
	foundP := false
	for _, tag := range tags[1:] {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		kv := strings.SplitN(tag, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		if strings.EqualFold(key, "p") {
			foundP = true
			pValue = strings.ToLower(value)
		}
	}
	if !foundP {
		addDMARC003(report, "p tag is missing")
		return
	}
	switch pValue {
	case "none":
		addDMARC002(report)
	case "quarantine", "reject":
		// ok
	default:
		addDMARC003(report, fmt.Sprintf("invalid p value: %s", pValue))
	}
}

func addDMARC002(report *Report) {
	if !hasFinding(report, "DMARC002") {
		report.Findings = append(report.Findings, Finding{Code: "DMARC002", Severity: "medium", Message: "DMARC policy is none"})
	}
}
func addDMARC003(report *Report, msg string) {
	if !hasFinding(report, "DMARC003") {
		report.Findings = append(report.Findings, Finding{Code: "DMARC003", Severity: "high", Message: msg})
	}
}

// hasEmptyP checks if a DKIM record has an empty p= tag.
func hasEmptyP(record string) bool {
	tags := strings.Split(record, ";")
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if strings.HasPrefix(tag, "p=") {
			value := strings.TrimPrefix(tag, "p=")
			if value == "" {
				return true
			}
			// if value is quoted empty? e.g., p=""
			value = strings.Trim(value, `"`)
			if value == "" {
				return true
			}
		}
	}
	return false
}

// isNotFound reports whether err is a DNS not found error.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// sortFindings sorts findings by Code, then Message.
func sortFindings(report *Report) {
	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Code != report.Findings[j].Code {
			return report.Findings[i].Code < report.Findings[j].Code
		}
		return report.Findings[i].Message < report.Findings[j].Message
	})
}

// Run executes the command-line interface.
func Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("email-dns-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dkimSelectors := fs.String("dkim", "", "comma-separated list of DKIM selectors")
	jsonOutput := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: email-dns-audit [--dkim selectors] [--json] domain")
		return 2
	}
	domain := fs.Arg(0)
	var selectors []string
	if *dkimSelectors != "" {
		selectors = strings.Split(*dkimSelectors, ",")
		for i, s := range selectors {
			selectors[i] = strings.TrimSpace(s)
		}
	}
	opts := Options{
		DKIMSelectors: selectors,
	}
	ctx := context.Background()
	report, err := Audit(ctx, domain, opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	hasHigh := false
	for _, f := range report.Findings {
		if f.Severity == "high" {
			hasHigh = true
			break
		}
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "error encoding JSON: %v\n", err)
			return 1
		}
	}
	if hasHigh {
		return 1
	}
	return 0
}
