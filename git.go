package cvebaser

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func (r *Repo) initGitRepo(clone, pull bool) error {
	var err error
	// Check dir exists
	exists, err := DirExists(r.dirPath)
	if err != nil {
		return fmt.Errorf("error checking dir exists: %v", err)
	}

	// If new repo flag is set, clone fresh repo from github and return early
	if clone {
		if exists {
			return fmt.Errorf("repo already exists: %s", r.dirPath)
		}

		r.gitRepo, err = git.PlainClone(r.dirPath, false, &git.CloneOptions{
			URL:      "https://github.com/cvebase/cvebase.com",
			Progress: os.Stdout,
		})
		if err != nil {
			if err == git.ErrRepositoryAlreadyExists {
				return errors.New("git repository already exists")
			}
			return fmt.Errorf("error cloning cvebase.com git repo: %v", err)
		}
		return nil
	}

	if !exists {
		return fmt.Errorf("repo does not exist: %s", r.dirPath)
	}

	// Open git repo at given path
	r.gitRepo, err = git.PlainOpen(r.dirPath)
	if err != nil {
		return fmt.Errorf("error loading git repo: %v", err)
	}

	// If pull flag is set, git pull to match remote origin
	if pull {
		w, err := r.gitRepo.Worktree()
		if err != nil {
			return err
		}
		err = w.Pull(&git.PullOptions{RemoteName: "origin"})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			return err
		}
	}

	return err
}

func (r *Repo) CheckFilenamesFromCommit(h string) ([]string, error) {
	ref, err := r.gitRepo.Head()
	if err != nil {
		return nil, err
	}

	cIter, err := r.gitRepo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return nil, err
	}

	var files []string
	// loop through each commit
	err = cIter.ForEach(func(c *object.Commit) error {
		if c.NumParents() == 0 {
			return nil
		}
		// collect files if commit hash matches
		if h == c.Hash.String() {
			files, err = getFilesModified(c)
			if err != nil {
				return err
			}
			// Exit commitIter after matching commit hash
			cIter.Close()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Dedupe values
	files = UniqStrings(files)

	return files, nil
}

// getFilesModified returns a slice of files modified in the given commit.
// Git DiffTree compares the content and mode of the blobs found via two tree objects.
// https://github.com/go-git/go-git/blob/218a744b6995a89f5c322aa58e79138d65392ea6/plumbing/object/difftree.go
func getFilesModified(commit *object.Commit) ([]string, error) {
	var files []string

	ct, err := commit.Tree() // current commit tree
	if err != nil {
		return nil, fmt.Errorf("error getting current tree from commit: %v", err)
	}
	prev, err := commit.Parent(0)
	// Exit if first commit and no parent
	if prev == nil {
		return nil, errors.New("first commit and no parent")
	}
	if err != nil {
		return nil, fmt.Errorf("error getting parent of commit: %v", err)
	}
	pt, err := prev.Tree() // previous commit tree
	if err != nil {
		return nil, fmt.Errorf("error getting tree from previous commit: %v", err)
	}
	changes, err := object.DiffTree(pt, ct)
	if err != nil {
		return nil, fmt.Errorf("error DiffTree on previous and current commit trees: %v", err)
	}
	patch, err := changes.Patch()
	if err != nil {
		return nil, fmt.Errorf("error getting patch changes: %v", err)
	}
	diffs := patch.FilePatches()
	for _, d := range diffs {
		_, to := d.Files()
		// Skip non-existing file; `to` is nil when file is deleted
		if to == nil {
			continue
		}
		file := to.Path()
		files = append(files, file)
	}
	return files, nil
}
