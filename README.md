# cvebaser [![Go Report](https://goreportcard.com/badge/github.com/cvebase/cvebaser)](https://goreportcard.com/report/github.com/cvebase/cvebaser)

cvebaser is a tool for interacting with [`cvebase/cvebase.com`](https://github.com/cvebase/cvebase.com) data, built in Go.

## Install

cvebaser requires **go1.15+** for installation.

```
GO111MODULE=on go get -u -v github.com/cvebase/cvebaser/cmd/cvebaser
```

## Usage

Lint all files:
```
cvebaser lint -r <path to cvebase.com repo>
```

Lint files from a specific commit:
```
cvebaser lint -r <path to cvebase.com repo> -c <git commit hash>
```

## License

[MIT License](LICENSE)
