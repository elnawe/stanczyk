package skc

import (
	"fmt"
	"strconv"
)

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

func FindFunctionsByName(code Code) []Function {
	var result []Function
	name := code.value.(string)

	for _, f := range TheProgram.chunks {
		if f.name == name {
			result = append(result, f)
		}
	}

	if len(result) == 0 {
		msg := fmt.Sprintf(MsgParseWordNotFound, name)
		ReportErrorAtLocation(msg, code.loc)
		ExitWithError(CodeCodegenError)
	}

	return result
}

func FindFunctionByIP(code Code) Function {
	ip := code.value.(int)
	return TheProgram.chunks[ip]
}

func ChangeValueOfFunction(functionIP, codeIP int, value FunctionCall) {
	TheProgram.chunks[functionIP].code[codeIP].value = value
}
