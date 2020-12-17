package lint

import (
	"testing"

	"github.com/cvebase/cvebaser"
	"github.com/stretchr/testify/assert"
)

func TestRepo_LintAll(t *testing.T) {
	repo, err := cvebaser.NewRepo("../../../cvebase.com", &cvebaser.GitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	linter := &Linter{Repo: repo}

	err = linter.LintAll(20)
	if err != nil {
		t.Fatal(err)
	}

}

func TestRepo_LintCommit(t *testing.T) {
	repo, err := cvebaser.NewRepo("../../../cvebase.com", &cvebaser.GitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	linter := &Linter{Repo: repo}
	err = linter.LintCommit("78cce2905f6a0b24cb24adbb46e922653627faf0")
	if err != nil {
		t.Fatal(err)
	}

}

func TestIsValidCVEDirPath(t *testing.T) {
	got := isValidCVESubPath("CVE-2016-0974", "../../../../cvebase.com/cve/2016/0xxx/CVE-2016-0974.md")
	assert.True(t, got)
}
