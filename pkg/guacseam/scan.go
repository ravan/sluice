package guacseam

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/ingestor/parser/common/scanner"
)

// ScanFailure records a scanner error without rejecting the base document.
type ScanFailure struct {
	Source string
	Err    error
}

// GUAC's combined parser logs scanner errors without returning them. Invoke
// its scanners explicitly so every failure survives in the pipeline receipt.
func scanPredicates(ctx context.Context, preds []assembler.IngestPredicates, purls []string, flags ScanFlags) []ScanFailure {
	scans := []struct {
		enabled bool
		source  string
		run     func() error
	}{
		{flags.Vulns, "osv", func() error {
			equal, cert, err := scanner.PurlsVulnScan(ctx, purls)
			if err == nil && len(preds) > 0 {
				preds[0].VulnEqual = append(preds[0].VulnEqual, equal...)
				preds[0].CertifyVuln = append(preds[0].CertifyVuln, cert...)
			}
			return err
		}},
		{flags.Licenses, "clearlydefined", func() error {
			legal, source, err := scanner.PurlsLicenseScan(ctx, purls)
			if err == nil && len(preds) > 0 {
				preds[0].CertifyLegal = append(preds[0].CertifyLegal, legal...)
				preds[0].HasSourceAt = append(preds[0].HasSourceAt, source...)
			}
			return err
		}},
		{flags.EOL, "eol", func() error {
			metadata, err := scanner.PurlsEOLScan(ctx, purls)
			if err == nil && len(preds) > 0 {
				preds[0].HasMetadata = append(preds[0].HasMetadata, metadata...)
			}
			return err
		}},
		{flags.DepsDev, "deps_dev", func() error {
			score, source, err := scanner.PurlsDepsDevScan(ctx, purls)
			if err == nil && len(preds) > 0 {
				preds[0].CertifyScorecard = append(preds[0].CertifyScorecard, score...)
				preds[0].HasSourceAt = append(preds[0].HasSourceAt, source...)
			}
			return err
		}},
	}
	var failed []ScanFailure
	for _, scan := range scans {
		if scan.enabled {
			if err := scan.run(); err != nil {
				failed = append(failed, ScanFailure{Source: scan.source, Err: err})
			}
		}
	}
	return failed
}
