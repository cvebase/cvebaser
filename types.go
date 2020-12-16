package cvebaser

type CVE struct {
	CVEID    string   `json:"-" yaml:"id"`
	Pocs     []string `json:"pocs,omitempty" yaml:"pocs,omitempty"`
	Courses  []string `json:"courses,omitempty" yaml:"courses,omitempty"`
	Writeups []string `json:"writeups,omitempty" yaml:"writeups,omitempty"`
	Advisory string   `json:"advisory,omitempty" yaml:"-"`
}

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
