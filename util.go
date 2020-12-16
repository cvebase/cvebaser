package cvebaser

import (
	"os"
	"sort"
)

// SortUniqStrings sorts and removes duplicates of a string slice
func SortUniqStrings(inSlice []string) []string {
	if len(inSlice) <= 1 {
		return inSlice
	}
	lessFn := func(i, j int) bool {
		return inSlice[i] < inSlice[j]
	}
	sort.Slice(inSlice, lessFn)
	return UniqStrings(inSlice)
}

// UniqStrings improves implementation of removeDuplicates
// avoids the excess work done by your use of append to remove elements
func UniqStrings(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	j := 0
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		s[j] = v
		j++
	}
	return s[:j]
}

// DirExists checks if a path exists and is a directory.
func DirExists(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err == nil && fi.IsDir() {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// Exists check if a file or directory exists.
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
