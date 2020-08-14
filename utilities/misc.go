package utilities

import "strings"

func ArrayContains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func StringsMatch(s1 string, s2 string) bool {
	return strings.ToLower(s1) == strings.ToLower(s2)
}

func StringContains(s1 string, s2 string) bool {
	return strings.Contains(strings.ToLower(s1), strings.ToLower(s2))
}
