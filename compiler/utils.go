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

func IsReservedCharacter(c byte) bool {
	return c == '[' || c == ']' || c == '(' || c == ')'
}

func IsDigit(c byte) bool {
	if _, err := strconv.Atoi(string(c)); err == nil {
		return true;
	}

	return false;
}

func AdvanceWithChecks(c *byte, line string, index *int) bool {
	if *index + 1 <= len(line) - 1 {
		testC := line[*index+1]
		if IsSpace(testC) || IsReservedCharacter(testC) {
			return false
		}
	}
	return Advance(c, line, index)
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
