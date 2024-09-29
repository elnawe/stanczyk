package skc

import (
	"os"
	"path/filepath"
	"strconv"
)

func GetRelativePath(to string) string {
	cwd, _ := os.Getwd()
	relPath, _ := filepath.Rel(cwd, to)
	return relPath
}

func IsSpace(c byte) bool {
	return c == ' ' || c == '\t'
}

func IsDigit(c byte) bool {
	if _, err := strconv.Atoi(string(c)); err == nil {
		return true;
	}

	return false;
}

func Advance(c *byte, line string, index *int) bool {
	*index++
	if *index > len(line) - 1 {
		return false
	}
	*c = line[*index]
	return true
}

func Contains[T comparable](s []T, e T) bool {
    for _, v := range s {
        if v == e {
            return true
        }
    }
    return false
}
