package cvebaser

import (
	"fmt"
	"log"
	"os"
	"path"
	"sync"

	"github.com/daehee/nvd"
)

func (r *Repo) LintCommit(commit string) (err error) {
	files, err := r.CheckFilenamesFromCommit(commit)
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
			err = lintCVE(path.Join(r.dirPath, p))
			if err != nil {
				log.Print(err)
			}
		case "researcher":
			err = lintResearcher(path.Join(r.dirPath, p))
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
func (r *Repo) LintAll(concurrency int) error {
	done := make(chan struct{})
	defer close(done)

	cvePaths, errStream := r.scanTree(done, "cve", ".md")
	researcherPaths, errStream := r.scanTree(done, "researcher", ".md")

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
		wantPath, _ := cveSubPath(cve.CVEID)
		fmt.Printf("[warn]\tinvalid dir for %s: got %s; want %s\n", cve.CVEID, cvePathToRelPath(p), wantPath)
	}

	// deduplicate values
	cve.dedupeSort()

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
		wantPath := researcherFileName(researcher.Alias)
		fmt.Printf("[warn]\tinvalid dir for %s: got %s; want %s\n", researcher.Alias, researcherPathToRelPath(p), wantPath)
	}

	// deduplicate values
	researcher.dedupeSort()

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
