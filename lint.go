package cvebaser

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/daehee/nvd"
)

type Linter struct {
	*Repo
}

func (lr *Linter) LintCommit(commit string) (err error) {
	files, err := lr.CheckFilenamesFromCommit(commit)
	if err != nil {
		return err
	}

	for _, p := range files {
		pType, err := PathIsType(p)
		if err != nil {
			return err
		}

		switch pType {
		case "cve":
			err = lintCVE(lr.GetFullPath(p))
			if err != nil {
				log.Print(err)
			}
		case "researcher":
			err = lintResearcher(lr.GetFullPath(p))
			if err != nil {
				log.Print(err)
			}
		default:
			return fmt.Errorf("unknown path type: %s", p)
		}
	}

	return nil
}

// LintAll is the concurrent variation of LintAll
func (lr *Linter) LintAll(concurrency int) error {
	done := make(chan struct{})
	defer close(done)

	cvePaths, errStream := lr.ScanTree(done, "cve", ".md")
	researcherPaths, errStream := lr.ScanTree(done, "researcher", ".md")

	// Start a number of goroutines to read and lint files.
	errWorkerStream := make(chan error)
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			lintConcurrent(done, cvePaths, lintCVE, errWorkerStream)
			lintConcurrent(done, researcherPaths, lintResearcher, errWorkerStream)
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		close(errWorkerStream)
	}()

	// Check for error thrown off by worker stream
	for err := range errWorkerStream {
		if err != nil {
			// TODO if err type indicates file rename, execute file move
			fmt.Printf("[error]\t%s\n", err)
		}
	}

	// Check whether the file walk failed
	if err := <-errStream; err != nil {
		return err
	}

	return nil
}

// scanFn is a callback function used for per-file operation while directory scanning
type scanFn func(string) error

// lintConcurrent is an abstracted concurrent linter function that
// accepts a linter scanFn for either lintCVE or lintResearcher
func lintConcurrent(done <-chan struct{}, paths <-chan string, lint scanFn, errStream chan<- error) {
	for p := range paths {
		err := lint(p)
		select {
		case errStream <- err:
		case <-done:
			return
		}
	}
}

func lintCVE(p string) (err error) {
	f, err := os.OpenFile(p, os.O_RDWR, 0755)
	if err != nil {
		return fmt.Errorf("error opening %s", p)
	}
	defer f.Close()

	var cve CVE
	err = ParseMDFile(f, &cve)
	if err != nil {
		return fmt.Errorf("error parsing cve file: %s: %v", cvePathToRelPath(p), err)
	}

	// Check CVE ID is correct
	if !nvd.IsCVEID(cve.CVEID) {
		return fmt.Errorf("invalid CVE ID %s: %s", cve.CVEID, cvePathToRelPath(p))
	}

	// Check CVE directory structure
	if !isValidCVESubPath(cve.CVEID, p) {
		wantPath, _ := CVESubPath(cve.CVEID)
		fmt.Printf("[warn]\tinvalid dir for %s: got %s; want %s\n", cve.CVEID, cvePathToRelPath(p), wantPath)
	}

	// deduplicate values
	cve.Pocs = sortUniqStrings(cve.Pocs)
	cve.Writeups = sortUniqStrings(cve.Writeups)
	cve.Courses = sortUniqStrings(cve.Courses)

	// TODO check required keys

	err = CompileToFile(f, p, cve)
	if err != nil {
		return fmt.Errorf("error compiling cve file: %v", err)
	}
	return nil
}

func lintResearcher(p string) (err error) {
	f, err := os.OpenFile(p, os.O_RDWR, 0755)
	if err != nil {
		return fmt.Errorf("error opening %s", p)
	}
	defer f.Close()

	var researcher Researcher
	err = ParseMDFile(f, &researcher)
	if err != nil {
		return fmt.Errorf("error parsing cve file: %v", err)
	}

	// Check researcher directory structure
	if !isValidResearcherSubPath(researcher.Alias, p) {
		wantPath := ResearcherSubPath(researcher.Alias)
		fmt.Printf("[warn]\tinvalid dir for %s: got %s; want %s\n", researcher.Alias, researcherPathToRelPath(p), wantPath)
	}

	// deduplicate values
	researcher.CVEs = sortUniqStrings(researcher.CVEs)

	// check required keys
	if len(researcher.CVEs) == 0 {
		fmt.Printf("[warn]\tno CVEs defined for %s: %s\n", researcher.Alias, researcherPathToRelPath(p))
	}

	// check each CVE ID if valid format
	for _, v := range researcher.CVEs {
		if !nvd.IsCVEID(v) {
			fmt.Printf("[warn]\tinvalid CVE ID %s: %s", v, researcherPathToRelPath(p))
		}
	}

	err = CompileToFile(f, p, researcher)
	if err != nil {
		return fmt.Errorf("error compiling researcher file: %v", err)
	}
	return nil

}

// cvePathToRelPath truncates cve filepath to relative path starting with year subdirectory
func cvePathToRelPath(p string) string {
	// ../../../../cvebase.com/cve/2018/0xxx/CVE-2018-0142.md ->
	// 2018/0xxx/CVE-2018-0142.md
	splitPath := strings.Split(p, "/")
	return strings.Join(splitPath[len(splitPath)-3:], "/")
}

// researcherPathToRelPath truncates researcher file path to relative path
func researcherPathToRelPath(p string) string {
	splitPath := strings.Split(p, "/")
	return strings.Join(splitPath[len(splitPath)-1:], "/")
}

// isValidCVESubPath checks if cve file is placed in correct year and sequence sub-directories.
func isValidCVESubPath(cveID, path string) bool {
	// Truncate path to slice containing relative path
	splitPath := strings.Split(path, "/")
	// ../../../../cvebase.com/cve/2018/xxx/CVE-2018-0142.md ->
	// [2018, xxx, CVE-2018-0142.md]
	splitPath = splitPath[len(splitPath)-3:]

	validPath, err := CVESubPath(cveID)
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

// isValidResearcherSubPath checks if researcher is placed in correct researcher subdirectory
func isValidResearcherSubPath(rAlias, path string) bool {
	// Truncate path to slice containing relative path
	splitPath := strings.Split(path, "/")
	// ../../../../cvebase.com/researcher/orange.md
	// becomes
	// [orange.md]
	splitPath = splitPath[len(splitPath)-1:]
	splitValid := []string{ResearcherSubPath(rAlias)}

	for i, v := range splitPath {
		if v != splitValid[i] {
			return false
		}
	}

	return true
}
