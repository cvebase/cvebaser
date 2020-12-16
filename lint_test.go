package cvebaser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRepo_LintAll(t *testing.T) {
	repo, err := NewRepo("../../cvebase.com", &GitOpts{})
	if err != nil {
		t.Fatal(err)
	}

	err = repo.LintAll(20)
	if err != nil {
		t.Fatal(err)
	}

}

func TestRepo_LintCommit(t *testing.T) {
	repo, err := NewRepo("../../cvebase.com", &GitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	err = repo.LintCommit("78cce2905f6a0b24cb24adbb46e922653627faf0")
	if err != nil {
		t.Fatal(err)
	}

}

func TestIsValidCVEDirPath(t *testing.T) {
	got := isValidCVESubPath("CVE-2016-0974", "../../../../cvebase.com/cve/2016/0xxx/CVE-2016-0974.md")
	assert.True(t, got)
}
