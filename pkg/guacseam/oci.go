package guacseam

import (
	"context"
	"time"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/oci"
)

// OCIReceiver collects SBOMs attached to OCI artifacts. Refs are image refs in
// image mode, or registry hosts in Registry mode.
type OCIReceiver struct {
	Refs     []string // image refs (image mode) or registry hosts (Registry mode)
	Registry bool     // true ⇒ collect whole registries (OciRegistryDataSources)
	Insecure bool     // plain-HTTP / skip-TLS, for local registries
	Poll     bool
	Interval time.Duration
}

// ociDataSources maps refs into the correct DataSources slice by mode.
func ociDataSources(refs []string, registry bool) *datasource.DataSources {
	ds := &datasource.DataSources{}
	for _, r := range refs {
		s := datasource.Source{Value: r}
		if registry {
			ds.OciRegistryDataSources = append(ds.OciRegistryDataSources, s)
		} else {
			ds.OciDataSources = append(ds.OciDataSources, s)
		}
	}
	return ds
}

// buildOCI builds GUAC's OCI (or OCI-registry) collector for the receiver.
func buildOCI(ctx context.Context, r OCIReceiver) (collector.Collector, error) {
	src, err := inmemsource.NewInmemDataSources(ociDataSources(r.Refs, r.Registry))
	if err != nil {
		return nil, err
	}
	rcOpts := oci.BuildRegClientOptions(oci.ExtractRegistryHosts(r.Refs), oci.OCIClientOptions{InsecureSkipTLSVerify: r.Insecure})
	if r.Registry {
		return oci.NewOCIRegistryCollector(ctx, src, r.Poll, r.Interval, rcOpts...), nil
	}
	return oci.NewOCICollector(ctx, src, r.Poll, r.Interval, rcOpts...), nil
}
