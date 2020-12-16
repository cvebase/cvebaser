package cvebaser

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/daehee/nvd"
)

type CVE struct {
	CVEID    string   `json:"-" yaml:"id"`
	Pocs     []string `json:"pocs,omitempty" yaml:"pocs,omitempty"`
	Courses  []string `json:"courses,omitempty" yaml:"courses,omitempty"`
	Writeups []string `json:"writeups,omitempty" yaml:"writeups,omitempty"`
	Advisory string   `json:"advisory,omitempty" yaml:"-"`
}

func (m *CVE) dedupeSort() {
	m.Pocs = sortUniqStrings(m.Pocs)
	m.Writeups = sortUniqStrings(m.Writeups)
	m.Courses = sortUniqStrings(m.Courses)
}

// isValidCVESubPath checks if cve file is placed in correct year and sequence sub-directories.
func isValidCVESubPath(cveID, path string) bool {
	// Truncate path to slice containing relative path
	splitPath := strings.Split(path, "/")
	// ../../../../cvebase.com/cve/2018/xxx/CVE-2018-0142.md ->
	// [2018, xxx, CVE-2018-0142.md]
	splitPath = splitPath[len(splitPath)-3:]

	validPath, err := cveSubPath(cveID)
	if err != nil {
		return false
	}
	splitValid := strings.Split(validPath, "/")

	// Compare equality of slice values
	for i, v := range splitPath {
		if v != splitValid[i] {
			return false
		}
	}

	return true
}

// cvePathToRelPath truncates cve filepath to relative path starting with year subdirectory
func cvePathToRelPath(p string) string {
	// ../../../../cvebase.com/cve/2018/0xxx/CVE-2018-0142.md ->
	// 2018/0xxx/CVE-2018-0142.md
	splitPath := strings.Split(p, "/")
	return strings.Join(splitPath[len(splitPath)-3:], "/")
}

// cveSubPath converts a CVE ID to cve relative path starting with year subdirectory
func cveSubPath(cveID string) (string, error) {
	year, sequence := nvd.ParseCVEID(cveID)
	seqDir, err := cveSeqDir(sequence)
	if err != nil {
		return "", fmt.Errorf("error parsing %s sequence to dir: %v", cveID, err)
	}
	return path.Join(strconv.Itoa(year), seqDir, fmt.Sprintf("%s.md", cveID)), nil
}

// cveSeqDir converts a cve sequence number to a "x"-padded sequence directory name
func cveSeqDir(seq int) (string, error) {
	seqStr := nvd.PadCVESequence(seq)
	subDir := seqStr[:len(seqStr)-3]
	if len(subDir) < 1 {
		return "", fmt.Errorf("CVE sequence invalid: %s -> %s", seqStr, subDir)
	}
	return fmt.Sprintf("%sxxx", subDir), nil
}
