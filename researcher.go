package cvebaser

import (
	"fmt"
	"strings"
)

type Researcher struct {
	Name        string   `json:"name" yaml:"name"`
	Alias       string   `json:"alias" yaml:"alias"`
	Nationality string   `json:"nationality" yaml:"nationality,omitempty"`
	Website     string   `json:"website" yaml:"website,omitempty"`
	Twitter     string   `json:"twitter" yaml:"twitter,omitempty"`
	Github      string   `json:"github" yaml:"github,omitempty"`
	Linkedin    string   `json:"linkedin" yaml:"linkedin,omitempty"`
	Hackerone   string   `json:"hackerone" yaml:"hackerone,omitempty"`
	Bugcrowd    string   `json:"bugcrowd" yaml:"bugcrowd,omitempty"`
	CVEs        []string `json:"cves" yaml:"cves"`
	Bio         string   `json:"bio" yaml:"-"`
}

func (m *Researcher) dedupeSort() {
	m.CVEs = sortUniqStrings(m.CVEs)
}

// isValidResearcherSubPath checks if researcher is placed in correct researcher subdirectory
func isValidResearcherSubPath(rAlias, path string) bool {
	// Truncate path to slice containing relative path
	splitPath := strings.Split(path, "/")
	// ../../../../cvebase.com/researcher/orange.md
	// becomes
	// [orange.md]
	splitPath = splitPath[len(splitPath)-1:]
	splitValid := []string{researcherFileName(rAlias)}

	for i, v := range splitPath {
		if v != splitValid[i] {
			return false
		}
	}

	return true
}

func researcherFileName(rAlias string) string {
	return fmt.Sprintf("%s.md", rAlias)
}

// researcherPathToRelPath truncates researcher file path to relative path
func researcherPathToRelPath(p string) string {
	splitPath := strings.Split(p, "/")
	return strings.Join(splitPath[len(splitPath)-1:], "/")
}
