package export

import (
	"testing"

	"github.com/cvebase/cvebaser"
	"github.com/stretchr/testify/assert"
)

func TestExporter_ExportCVE(t *testing.T) {
	repo, err := cvebaser.NewRepo("../../../cvebase.com", &cvebaser.GitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	exporter := &Exporter{Repo: repo}

	err = exporter.ExportCVE("test.json")
	assert.NoError(t, err)
}
