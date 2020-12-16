package cvebaser

import (
	"testing"
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
