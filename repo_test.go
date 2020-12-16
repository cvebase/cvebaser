package cvebaser

import (
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
)

func TestNewRepo(t *testing.T) {
	tests := []struct {
		wantError bool
		existing  bool
		gitClone  bool
		gitPull   bool
	}{
		// clone new repo; no existing dir -> no error
		{false, false, true, false},
		// clone new repo; existing dir -> error
		{true, true, true, false},
		// existing repo; existing dir -> no error
		{false, true, false, false},
		// existing repo; no existing dir -> error
		{true, true, false, false},
		// existing repo; pull updates -> error
		{false, true, false, true},
	}

	var err error
	testRepo := "tmp/cvebase.com"

	for _, tt := range tests {
		err = cleanup()
		if err != nil {
			t.Fatal(err)
		}

		err = setup()
		if err != nil {
			t.Fatal(err)
		}

		if tt.existing {
			_, err = git.PlainClone(testRepo, false, &git.CloneOptions{
				URL:      "https://github.com/cvebase/cvebase.com",
				Progress: os.Stdout,
				Depth:    1,
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		_, err := NewRepo(testRepo,
			&GitOpts{
				Clone: tt.gitClone,
				Pull:  tt.gitPull,
			})
		if !tt.wantError && err != nil {
			t.Error(err)
		}

		err = cleanup()
		if err != nil {
			t.Fatal(err)
		}
	}

}

func TestNewRepo_EmptyGitOpts(t *testing.T) {
	var err error

	t.Log("setup")
	err = setup()
	if err != nil {
		t.Fatal(err)
	}

	testRepo := "tmp/cvebase.com"

	_, err = git.PlainClone(testRepo, false, &git.CloneOptions{
		URL:      "https://github.com/cvebase/cvebase.com",
		Progress: os.Stdout,
		Depth:    1,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewRepo(testRepo, &GitOpts{})
	assert.NoError(t, err)

	t.Log("cleanup")
	err = cleanup()
	if err != nil {
		t.Fatal(err)
	}
}

func TestWantPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		// valid paths
		{"cve/2016/1000xxx/CVE-2016-1000123.md", "cve/2016/1000xxx/CVE-2016-1000123.md"},
		{"researcher/ma7h1as.md", "researcher/ma7h1as.md"},
		// invalid paths
		{"cve/2016/000xxx/CVE-2016-1000123.md", "cve/2016/1000xxx/CVE-2016-1000123.md"},
		{"cve/2016/1000xxx/CVE-2016-01000123.md", "cve/2016/1000xxx/CVE-2016-1000123.md"},
	}

	for _, tt := range tests {
		got, err := WantPath(tt.path)
		assert.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}

}

func TestPathIsType(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"cve/2016/1000xxx/CVE-2016-1000123.md", "cve"},
		{"researcher/ma7h1as.md", "researcher"},
	}

	for _, tt := range tests {
		got, err := PathIsType(tt.path)
		assert.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}
}

func setup() error {
	err := os.MkdirAll("tmp", 0755)
	if err != nil {
		return err
	}
	return nil
}

func cleanup() error {
	err := os.RemoveAll("tmp")
	if err != nil {
		return err
	}
	return nil
}

func TestCVESubPath(t *testing.T) {
	want := "2020/14xxx/CVE-2020-14882.md"
	got, err := CVESubPath("CVE-2020-14882")
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestCVESeqDir(t *testing.T) {
	tests := []struct {
		sequence int
		want     string
	}{
		{974, "0xxx"},
		{14882, "14xxx"},
		{97, "0xxx"},
	}

	for _, tt := range tests {
		got, err := cveSeqDir(tt.sequence)
		assert.NoError(t, err)
		assert.Equal(t, got, tt.want)
	}
}
