package cvebaser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/daehee/nvd"
	"github.com/go-git/go-git/v5"
	"github.com/karrick/godirwalk"
)

type Repo struct {
	DirPath string
	gitRepo *git.Repository
	gitOpts *GitOpts
}

type GitOpts struct {
	Clone bool
	Pull  bool
}

func NewRepo(p string, g *GitOpts) (*Repo, error) {
	if p == "" {
		return nil, errors.New("repo path not set")
	}
	r := &Repo{
		DirPath: p,
	}

	err := r.initGitRepo(g.Clone, g.Pull)
	if err != nil {
		return nil, fmt.Errorf("error initializing git for new Repo object: %v", err)
	}
	return r, nil
}

// GetFullPath converts relative file path to full path including the base directory
func (r *Repo) GetFullPath(p string) string {
	return path.Join(r.DirPath, p)
}

// ScanTree generates a channel of filepaths from sub-directory in the repo,
// filtering paths with provided file extension e.g. `.md`.
// A buffered error channel returns any errors encountered during the dirwalk.
func (r *Repo) ScanTree(done <-chan struct{}, subDir string, fileExt string) (<-chan string, <-chan error) {
	pathStream := make(chan string)
	errStream := make(chan error, 1)
	go func() {
		// Close the paths channel after walk returns
		defer close(pathStream)
		// Select block not needed for this send, since errStream is buffered
		errStream <- godirwalk.Walk(path.Join(r.DirPath, subDir), &godirwalk.Options{
			Callback: func(osPathname string, de *godirwalk.Dirent) error {
				if strings.Contains(osPathname, fileExt) {
					select {
					case pathStream <- osPathname:
					case <-done:
						// Abort the walk if done is closed
						return errors.New("walk canceled")
					}
				}
				return nil
			},
			Unsorted: true,
		})
	}()
	return pathStream, errStream
}

// ScanCVE returns a channel of all CVE objects in the repo.
// A buffered error channel returns any errors encountered during the dirwalk.
func (r *Repo) ScanCVE(ctx context.Context) (<-chan CVE, <-chan error) {
	cveStream := make(chan CVE)
	errStream := make(chan error, 1)
	go func() {
		// Close the paths channel after walk returns
		defer close(cveStream)
		defer close(errStream)
		// Select block not needed for this send, since errStream is buffered
		errStream <- godirwalk.Walk(path.Join(r.DirPath, "cve"), &godirwalk.Options{
			Callback: func(osPathname string, de *godirwalk.Dirent) error {
				if strings.Contains(osPathname, ".md") {
					f, err := os.OpenFile(osPathname, os.O_RDWR, 0755)
					if err != nil {
						return fmt.Errorf("error opening %s", osPathname)
					}
					defer f.Close()

					cve, err := ParseCVEMDFile(f)
					if err != nil {
						return err
					}

					select {
					case cveStream <- cve:
					case <-ctx.Done():
						// Abort the walk if done is closed
						return errors.New("walk canceled")
					}
				}
				return nil
			},
			Unsorted: false, // Set to sort for consistent ordered results
		})
	}()
	return cveStream, errStream
}

// WantPath attempts to repair a provided cve or researcher filepath
// for cases where the file was linted and moved in a later commit.
// Returns a relative path to cve or researcher file.
func WantPath(p string) (string, error) {
	var newPath string
	pathToFileNameSansExt := func(p string) string {
		sp := strings.Split(p, "/")
		fileName := sp[len(sp)-1]
		return strings.TrimSuffix(fileName, filepath.Ext(fileName))
	}

	pType, err := PathIsType(p)
	if err != nil {
		return "", err
	}
	switch pType {
	case "cve":
		cveID := pathToFileNameSansExt(p)
		// TODO refactor this and use for linter as well
		if !nvd.IsCVEIDStrict(cveID) {
			cveID = nvd.FixCVEID(cveID)
		}
		wdp, err := CVESubPath(cveID)
		if err != nil {
			return "", err
		}
		newPath = path.Join("cve", wdp)
	case "researcher":
		// TODO parse file content and grab researcher alias
		wdp := ResearcherSubPath(pathToFileNameSansExt(p))
		newPath = path.Join("researcher", wdp)
	default:
		return "", fmt.Errorf("could not match path to CVE or Researcher type: %s", p)
	}

	// if p == newPath {
	// 	return "", fmt.Errorf("want path same as given path: %s -> %s", p, newPath)
	// }

	return newPath, nil
}

// PathIsType returns either "cve" or "researcher" based on
// directory structure of given relative path to cve or researcher file
func PathIsType(p string) (string, error) {
	patternTypes := []struct {
		t string
		p string
	}{
		{"cve", "cve/*/*/*.md"},
		{"researcher", "researcher/*.md"},
	}
	var matchedType string

	for _, v := range patternTypes {
		matched, err := filepath.Match(v.p, p)
		if err != nil {
			return "", fmt.Errorf("error matching path %s with %s", p, v.p)
		}
		if matched {
			matchedType = v.t
		}
	}

	if matchedType == "" {
		return "", fmt.Errorf("unable to match path: %s", p)
	}

	return matchedType, nil
}

// CVESubPath converts a CVE ID to cve relative path starting with year subdirectory
func CVESubPath(cveID string) (string, error) {
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

func ResearcherSubPath(rAlias string) string {
	return fmt.Sprintf("%s.md", rAlias)
}

func CvebaseURL(cveID string) string {
	if !nvd.IsCVEIDStrict(cveID) {
		return ""
	}
	year, seq := nvd.ParseCVEID(cveID)
	return fmt.Sprintf("https://www.cvebase.com/cve/%d/%d", year, seq)
}
