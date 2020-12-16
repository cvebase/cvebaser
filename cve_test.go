package cvebaser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCVE_DedupeSort(t *testing.T) {
	tests := []struct {
		cve     CVE
		wantCVE CVE
	}{
		{
			CVE{
				CVEID:    "CVE-2020-14882",
				Pocs:     []string{"https://github.com", "https://github.com", "https://github.com", "https://exploit-db.com"},
				Writeups: []string{"https://github.com", "https://github.com", "https://github.com", "https://exploit-db.com"},
				Courses:  []string{"https://github.com", "https://github.com", "https://github.com", "https://exploit-db.com"},
				Advisory: "lorem ipsum dolor",
			},
			CVE{
				CVEID:    "CVE-2020-14882",
				Pocs:     []string{"https://exploit-db.com", "https://github.com"},
				Writeups: []string{"https://exploit-db.com", "https://github.com"},
				Courses:  []string{"https://exploit-db.com", "https://github.com"},
				Advisory: "lorem ipsum dolor",
			},
		},
	}

	for _, tt := range tests {
		tt.cve.dedupeSort()
		assert.EqualValues(t, tt.wantCVE.Pocs, tt.cve.Pocs)
		assert.EqualValues(t, tt.wantCVE.Writeups, tt.cve.Writeups)
		assert.EqualValues(t, tt.wantCVE.Courses, tt.cve.Courses)
	}
}

func TestCVESubPath(t *testing.T) {
	want := "2020/14xxx/CVE-2020-14882.md"
	got, err := cveSubPath("CVE-2020-14882")
	assert.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestIsValidCVEDirPath(t *testing.T) {
	got := isValidCVESubPath("CVE-2016-0974", "../../../../cvebase.com/cve/2016/0xxx/CVE-2016-0974.md")
	assert.True(t, got)
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
