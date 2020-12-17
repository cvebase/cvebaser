package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/cvebase/cvebaser"
	"github.com/cvebase/cvebaser/export"
	"github.com/cvebase/cvebaser/lint"
	"github.com/gobwas/cli"
)

func main() {
	cli.Main(cli.Commands{
		"lint":   new(lintCommand),
		"export": new(exportCommand),
	})
}

type lintCommand struct {
	commit   string
	repoPath string
}

func (cmd *lintCommand) DefineFlags(fs *flag.FlagSet) {
	fs.StringVar(&cmd.commit,
		"c", cmd.commit,
		"commit hash",
	)
	fs.StringVar(&cmd.repoPath,
		"r", cmd.repoPath,
		"path to cvebase.com repo",
	)
	// TODO add concurrency option
}

func (cmd *lintCommand) Run(_ context.Context, _ []string) error {
	repo, err := cvebaser.NewRepo(cmd.repoPath, &cvebaser.GitOpts{})
	if err != nil {
		return err
	}
	linter := &lint.Linter{Repo: repo}

	linter.Start()
	if cmd.commit != "" {
		err = linter.LintCommit(cmd.commit)
		if err != nil {
			return err
		}
	} else {
		err = linter.LintAll(20)
		if err != nil {
			return err
		}
	}
	linter.End()

	// TODO print number of files modified

	fmt.Printf("\nTime Completed: %v\n", linter.Stats.Duration().Round(time.Second))

	return nil
}

type exportCommand struct {
	repoPath string
	outFile  string
}

func (cmd *exportCommand) DefineFlags(fs *flag.FlagSet) {
	fs.StringVar(&cmd.repoPath,
		"r", cmd.repoPath,
		"path to cvebase.com repo",
	)
	fs.StringVar(&cmd.outFile, "o", cmd.outFile, "file to save output result")
}

func (cmd *exportCommand) Run(_ context.Context, _ []string) error {
	repo, err := cvebaser.NewRepo(cmd.repoPath, &cvebaser.GitOpts{})
	if err != nil {
		return err
	}

	exporter := &export.Exporter{Repo: repo}
	err = exporter.ExportCVE(cmd.outFile)
	if err != nil {
		return err
	}

	return nil
}
