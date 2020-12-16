package cvebaser

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/daehee/nvd"
	"github.com/go-git/go-git/v5"
	"github.com/karrick/godirwalk"
)

type Repo struct {
	dirPath string
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
		dirPath: p,
	}

	err := r.initGitRepo(g.Clone, g.Pull)
	if err != nil {
		return nil, fmt.Errorf("error initializing git for new Repo object: %v", err)
	}
	return r, nil
}

// GetFullPath converts relative file path to full path including the base directory
func (r *Repo) GetFullPath(p string) string {
	return path.Join(r.dirPath, p)
}

// scanFn is a callback function used for per-file operation while directory scanning
type scanFn func(string) error

// scanTree generates a channel of filepaths from sub-directory in the repo,
// filtering paths with provided file extension e.g. `.md`.
// A buffered error channel returns any errors encountered during the dirwalk.
func (r *Repo) scanTree(done <-chan struct{}, subDir string, fileExt string) (<-chan string, <-chan error) {
	pathStream := make(chan string)
	errStream := make(chan error, 1)
	go func() {
		// Close the paths channel after walk returns
		defer close(pathStream)
		// Select block not needed for this send, since errStream is buffered
		errStream <- godirwalk.Walk(path.Join(r.dirPath, subDir), &godirwalk.Options{
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
		wdp, err := cveSubPath(cveID)
		if err != nil {
			return "", err
		}
		newPath = path.Join("cve", wdp)
	case "researcher":
		// TODO parse file content and grab researcher alias
		wdp := researcherFileName(pathToFileNameSansExt(p))
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