package export

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"

	"github.com/cvebase/cvebaser"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cveStream, errStream := ex.ScanCVE(ctx)

	// Ordering matters, so don't spin up additional workers to process cveStream
	// Stream to output in linear pipeline

	f, err := os.Create(op)
	if err != nil {
		return err
	}
	// Init buffered writer
	w := bufio.NewWriter(f)

Loop:
	for {
		select {
		case v, ok := <-cveStream:
			// when receive signal cveSteam closed
			if ok == false {
				break Loop
			}

			// Skip if CVE has no POCs
			if len(v.Pocs) == 0 {
				break
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
		case err = <-errStream:
			if err != nil {
				f.Close()
				return err
			}
		}
	}

	w.Flush()
	return f.Close()
}
