package export

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/cvebase/cvebaser"
	"github.com/karrick/godirwalk"
)

type CVEPocs struct {
	CVEID string   `json:"cve_id"`
	URL   string   `json:"url"`
	Pocs  []string `json:"pocs"`
}

type Exporter struct {
	*cvebaser.Repo
}

func (ex *Exporter) ExportCVE(op string) error {
	// Initialize buffered channel for error
	errStream := make(chan error, 1)

	done := make(chan struct{})
	defer close(done)

	cveStream := ex.scanCVE(done, errStream)

	// Ordering matters, so don't spin up additional workers to process cveStream
	// Stream to output in linear pipeline

	f, err := os.Create(op)
	if err != nil {
		return err
	}
	// Init buffered writer
	w := bufio.NewWriter(f)

	for v := range cveStream {
		// Skip if CVE has no POCs
		if len(v.Pocs) == 0 {
			continue
		}

		var b bytes.Buffer
		jsonEncoder := json.NewEncoder(&b)
		// jsonEncoder.SetIndent("", "    ")
		err = jsonEncoder.Encode(CVEPocs{
			CVEID: v.CVEID,
			URL:   cvebaser.CvebaseURL(v.CVEID),
			Pocs:  v.Pocs,
		})
		if err != nil {
			return err
		}
		_, err = w.Write(b.Bytes())
		if err != nil {
			return err
		}

		select {
		case err = <-errStream:
			f.Close()
			return err
		case <-done:
			f.Close()
			return errors.New("canceled")
		default:
		}
	}

	w.Flush()
	return f.Close()
}

func (ex *Exporter) scanCVE(done <-chan struct{}, errStream chan<- error) <-chan cvebaser.CVE {
	cveStream := make(chan cvebaser.CVE)
	go func() {
		// Close the paths channel after walk returns
		defer close(cveStream)
		// Select block not needed for this send, since errStream is buffered
		errStream <- godirwalk.Walk(path.Join(ex.DirPath, "cve"), &godirwalk.Options{
			Callback: func(osPathname string, de *godirwalk.Dirent) error {
				if strings.Contains(osPathname, ".md") {
					f, err := os.OpenFile(osPathname, os.O_RDWR, 0755)
					if err != nil {
						return fmt.Errorf("error opening %s", osPathname)
					}
					defer f.Close()

					cve, err := cvebaser.ParseCVEMDFile(f)
					if err != nil {
						return err
					}

					select {
					case cveStream <- cve:
					case <-done:
						// Abort the walk if done is closed
						return errors.New("walk canceled")
					}
				}
				return nil
			},
			Unsorted: false, // Set to sort for consistent ordered results
		})
	}()
	return cveStream
}
