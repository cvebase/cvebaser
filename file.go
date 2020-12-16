package cvebaser

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/gohugoio/hugo/parser/pageparser"
	"gopkg.in/yaml.v3"
)

// ParseCVEMDFile reads markdown file contents containing YAML and markdown
// and returns CVE data struct
func ParseCVEMDFile(reader io.Reader) (cve CVE, err error) {
	pf, err := pageparser.ParseFrontMatterAndContent(reader)
	if err != nil {
		return cve, err
	}
	fm, err := yaml.Marshal(pf.FrontMatter)
	if err != nil {
		return cve, err
	}
	err = yaml.Unmarshal(fm, &cve)
	if err != nil {
		return cve, err
	}
	cve.Advisory = string(pf.Content)
	return
}

// ParseResearcherMDFile reads markdown file contents containing YAML and markdown
// and returns Researcher data struct
func ParseResearcherMDFile(reader io.Reader) (researcher Researcher, err error) {
	pf, err := pageparser.ParseFrontMatterAndContent(reader)
	if err != nil {
		return researcher, err
	}
	fm, err := yaml.Marshal(pf.FrontMatter)
	if err != nil {
		return researcher, err
	}
	err = yaml.Unmarshal(fm, &researcher)
	if err != nil {
		return researcher, err
	}
	researcher.Bio = string(pf.Content)
	return
}

// ParseMDFile reads markdown file contents containing YAML and markdown
// and returns either CVE or Researcher data struct
func ParseMDFile(r io.Reader, tPtr interface{}) error {
	pf, err := pageparser.ParseFrontMatterAndContent(r)
	if err != nil {
		return fmt.Errorf("error parsing front matter: %v", err)
	}
	fm, err := yaml.Marshal(pf.FrontMatter)
	if err != nil {
		return fmt.Errorf("error marshaling yaml: %v", err)
	}
	err = yaml.Unmarshal(fm, tPtr)
	if err != nil {
		return fmt.Errorf("erorr unmarshaling yaml: %v", err)
	}

	// Set field value for markdown text depending on CVE or Researcher
	switch t := tPtr.(type) {
	case *CVE:
		t.Advisory = string(pf.Content)
	case *Researcher:
		t.Bio = string(pf.Content)
	default:
		return fmt.Errorf("unknown type: %+v", tPtr)
	}

	return nil
}

const yamlDelimLf = "---\n"

func CompileToFile(
	f *os.File,
	path string,
	t interface{}, /* CVE or Researcher to marshal */
) error {
	// Configure yaml encoding for custom indent spacing
	var d bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&d)
	// go-yaml v3 now defaults to 4 spaces, so manually set to 2
	yamlEncoder.SetIndent(2)
	err := yamlEncoder.Encode(t)
	if err != nil {
		return fmt.Errorf("error marshaling yaml to %s", path)
	}
	yamlEncoder.Close()

	// Lead with marshaling first so that
	// if fails doesn't error with a pre-maturely truncated file
	// d, err := yaml.Marshal(t)

	// TODO Check if file contents have changed before writing, otherwise return early

	// Clear file for writing
	f.Truncate(0)
	f.Seek(0, 0)

	_, err = f.WriteString(yamlDelimLf)
	if err != nil {
		return fmt.Errorf("error writing to %s: %v", path, err)
	}
	_, err = f.Write(d.Bytes())
	if err != nil {
		return fmt.Errorf("error writing to %s: %v", path, err)
	}
	_, err = f.WriteString(yamlDelimLf)
	if err != nil {
		return fmt.Errorf("error writing to %s: %v", path, err)
	}

	// Write markdown content from struct field depending on type CVE or Researcher
	switch t := t.(type) {
	case CVE:
		_, err = f.WriteString(t.Advisory)
		if err != nil {
			return fmt.Errorf("error writing to %s: %v", path, err)
		}
	case Researcher:
		_, err = f.WriteString(t.Bio)
		if err != nil {
			return fmt.Errorf("error writing to %s: %v", path, err)
		}
	default:
		return fmt.Errorf("unknown type: %+v", t)
	}

	return nil
}
