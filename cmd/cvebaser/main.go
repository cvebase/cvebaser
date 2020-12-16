package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/cvebase/cvebaser"
	"github.com/gobwas/cli"
)

func main() {
	cli.Main(cli.Commands{
		"lint": new(lintCommand),
	})
}

type lintCommand struct {
	commit   string
	repoPath string
}

func (l *lintCommand) DefineFlags(fs *flag.FlagSet) {
	fs.StringVar(&l.commit,
		"c", l.commit,
		"commit hash",
	)
	fs.StringVar(&l.repoPath,
		"r", l.repoPath,
		"path to cvebase.com repo",
	)
	// TODO add concurrency option
}

func (l *lintCommand) Run(_ context.Context, _ []string) error {
	repo, err := cvebaser.NewRepo(l.repoPath, &cvebaser.GitOpts{})
	if err != nil {
		return err
	}
	linter := &cvebaser.Linter{Repo: repo}

	start := time.Now()
	if l.commit != "" {
		err = linter.LintCommit(l.commit)
		if err != nil {
			return err
		}
	} else {
		err = linter.LintAll(20)
		if err != nil {
			return err
		}
	}
	duration := time.Since(start)

	// TODO print number of files modified

	fmt.Printf("\n--- %.1f seconds ---\n", duration.Seconds())

	return nil
}
