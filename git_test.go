package cvebaser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRepo_CheckFilenamesFromCommit(t *testing.T) {
	repo, err := NewRepo("../../cvebase.com", &GitOpts{
		Clone: false,
		Pull:  false,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"cve/2016/1000xxx/CVE-2016-1000123.md",
		"cve/2016/1000xxx/CVE-2016-1000124.md",
		"cve/2016/1000xxx/CVE-2016-1000125.md",
		"cve/2017/1002xxx/CVE-2017-1002000.md",
		"researcher/ma7h1as.md",
		"researcher/oleksandr-mirosh.md",
	}
	got, err := repo.CheckFilenamesFromCommit("0c385b281be84bff35778ec134853b00a5ef8e16")
	assert.NoError(t, err)
	assert.EqualValues(t, got, want)
}
