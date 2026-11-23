package runner

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestProviderConfigListsSourcesThatAcceptKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider-config.yaml")
	if err := createProviderConfigYAML(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string][]string{}
	if err := yaml.Unmarshal(data, keys); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"alienvault", "urlscan", "virustotal"} {
		if _, ok := keys[name]; !ok {
			t.Errorf("provider config is missing %q: %s", name, data)
		}
	}
	if _, ok := keys["waybackarchive"]; ok {
		t.Errorf("provider config lists keyless source waybackarchive: %s", data)
	}
}
