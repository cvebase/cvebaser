package cvebaser

import (
	"os"
	"sort"
)

// sortUniqStrings sorts and removes duplicates of a string slice
func sortUniqStrings(inSlice []string) []string {
	if len(inSlice) <= 1 {
		return inSlice
	}
	lessFn := func(i, j int) bool {
		return inSlice[i] < inSlice[j]
	}
	sort.Slice(inSlice, lessFn)
	return uniqStrings(inSlice)
}

// uniqStrings improves implementation of removeDuplicates
// avoids the excess work done by your use of append to remove elements
// TODO replace removeDuplicates function
func uniqStrings(s []string) []string {
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

func removeDuplicates(elements []string) []string {
	// Use map to record duplicates as we find them.
	encountered := map[string]bool{}
	result := make([]string, 0)

	for v := range elements {
		if encountered[elements[v]] == true {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[elements[v]] = true
			// Append to result slice.
			result = append(result, elements[v])
		}
	}
	return result
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
