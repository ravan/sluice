package guacseam

import (
	"context"
	"testing"

	"github.com/guacsec/guac/pkg/handler/collector/oci"
)

func TestOCIDataSourcesImageMode(t *testing.T) {
	ds := ociDataSources([]string{"reg/a:1", "reg/b:2"}, false)
	if len(ds.OciRegistryDataSources) != 0 {
		t.Errorf("OciRegistryDataSources = %+v, want empty", ds.OciRegistryDataSources)
	}
	if len(ds.OciDataSources) != 2 {
		t.Fatalf("OciDataSources len = %d, want 2", len(ds.OciDataSources))
	}
	if ds.OciDataSources[0].Value != "reg/a:1" || ds.OciDataSources[1].Value != "reg/b:2" {
		t.Errorf("OciDataSources = %+v, want [reg/a:1 reg/b:2] in order", ds.OciDataSources)
	}
}

func TestOCIDataSourcesRegistryMode(t *testing.T) {
	ds := ociDataSources([]string{"reg/a:1", "reg/b:2"}, true)
	if len(ds.OciDataSources) != 0 {
		t.Errorf("OciDataSources = %+v, want empty", ds.OciDataSources)
	}
	if len(ds.OciRegistryDataSources) != 2 {
		t.Fatalf("OciRegistryDataSources len = %d, want 2", len(ds.OciRegistryDataSources))
	}
	if ds.OciRegistryDataSources[0].Value != "reg/a:1" || ds.OciRegistryDataSources[1].Value != "reg/b:2" {
		t.Errorf("OciRegistryDataSources = %+v, want [reg/a:1 reg/b:2] in order", ds.OciRegistryDataSources)
	}
}

func TestBuildOCIType(t *testing.T) {
	ctx := context.Background()

	c, err := buildOCI(ctx, OCIReceiver{Refs: []string{"reg/a:1"}})
	if err != nil {
		t.Fatalf("buildOCI returned error: %v", err)
	}
	if c == nil {
		t.Fatal("buildOCI returned nil collector")
	}
	if c.Type() != oci.OCICollector {
		t.Errorf("Type() = %q, want %q", c.Type(), oci.OCICollector)
	}

	rc, err := buildOCI(ctx, OCIReceiver{Refs: []string{"reg/a:1"}, Registry: true})
	if err != nil {
		t.Fatalf("buildOCI (registry) returned error: %v", err)
	}
	if rc == nil {
		t.Fatal("buildOCI (registry) returned nil collector")
	}
	if rc.Type() != oci.OCIRegistryCollector {
		t.Errorf("Type() = %q, want %q", rc.Type(), oci.OCIRegistryCollector)
	}
}
