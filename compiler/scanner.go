package skc

import (
	"bufio"
	"strconv"
	"strings"
)

type TokenType int

const (
	// CONSTANTS
	TOKEN_CONSTANT_CHAR TokenType = iota
	TOKEN_CONSTANT_FALSE
	TOKEN_CONSTANT_INT
	TOKEN_CONSTANT_STR
	TOKEN_CONSTANT_TRUE

	// Types
	TOKEN_ANY
	TOKEN_BOOL
	TOKEN_STARBOOL
	TOKEN_CHAR
	TOKEN_STARCHAR
	TOKEN_INT
	TOKEN_STARINT
	TOKEN_PARAPOLY
	TOKEN_PTR
	TOKEN_STR
	TOKEN_STARSTR

	// Macros
	TOKEN_ASM
	TOKEN_AT_BODY
	TOKEN_CURLY_BRACKET_CLOSE
	TOKEN_CURLY_BRACKET_OPEN

	// Flow Control
	TOKEN_CASE
	TOKEN_ELSE
	TOKEN_IF
	TOKEN_FI
	TOKEN_LOOP
	TOKEN_UNTIL
	TOKEN_WHILE

	TOKEN_BANG
	TOKEN_C_BANG
	TOKEN_AT
	TOKEN_C_AT

	TOKEN_AMPERSAND

	// Single characters
	TOKEN_BRACKET_CLOSE
	TOKEN_BRACKET_OPEN
	TOKEN_PAREN_CLOSE
	TOKEN_PAREN_OPEN

	// NEW
	TOKEN_DASH_DASH_DASH
	TOKEN_LET
	TOKEN_IN
	TOKEN_DONE

	// Reserved Words
	TOKEN_ARGC
	TOKEN_ARGV
	TOKEN_BANG_EQUAL
	TOKEN_CONST
	TOKEN_EQUAL
	TOKEN_FN
	TOKEN_GREATER
	TOKEN_GREATER_EQUAL
	TOKEN_LEAVE
	TOKEN_LESS
	TOKEN_LESS_EQUAL
	TOKEN_MINUS
	TOKEN_PERCENT
	TOKEN_PLUS
	TOKEN_RET
	TOKEN_RIGHT_ARROW
	TOKEN_SLASH
	TOKEN_STAR
	TOKEN_THIS
	TOKEN_USING
	TOKEN_VAR

	// Specials
	TOKEN_EOF
	TOKEN_WORD
)

type reserved struct {
	word  string
	typ   TokenType
}

var reservedWords = []reserved{
	// CONSTANTS
	reserved{typ: TOKEN_CONSTANT_FALSE, word: "false"  },
	reserved{typ: TOKEN_CONSTANT_TRUE,  word: "true"   },

	// DATA TYPES
	reserved{typ: TOKEN_ANY,            word: "any"    },
	reserved{typ: TOKEN_BOOL,           word: "bool"   },
	reserved{typ: TOKEN_STARBOOL,       word: "*bool"  },
	reserved{typ: TOKEN_CHAR,           word: "char"   },
	reserved{typ: TOKEN_STARCHAR,       word: "*char"  },
	reserved{typ: TOKEN_INT,            word: "int"    },
	reserved{typ: TOKEN_STARINT,        word: "*int"   },
	reserved{typ: TOKEN_PTR,            word: "ptr"    },
	reserved{typ: TOKEN_STR,            word: "str"    },
	reserved{typ: TOKEN_STARSTR,        word: "*str"   },

	// MACROS
	reserved{typ: TOKEN_ASM,            word: "asm"    },
	reserved{typ: TOKEN_AT_BODY,        word: "@body"  },

	reserved{typ: TOKEN_DASH_DASH_DASH, word: "---"    },
	reserved{typ: TOKEN_LET,            word: "let"    },
	reserved{typ: TOKEN_IN,             word: "in"     },
	reserved{typ: TOKEN_DONE,           word: "done"   },

	reserved{typ: TOKEN_BANG,           word: "!"      },
	reserved{typ: TOKEN_AT,             word: "@"      },
	reserved{typ: TOKEN_C_BANG,         word: "!c"     },
	reserved{typ: TOKEN_C_AT,           word: "@c"     },

	reserved{typ: TOKEN_ELSE,           word: "else"   },
	reserved{typ: TOKEN_FI,             word: "fi"     },
	reserved{typ: TOKEN_IF,             word: "if"     },
	reserved{typ: TOKEN_LOOP,           word: "loop"   },
	reserved{typ: TOKEN_UNTIL,          word: "until"  },
	reserved{typ: TOKEN_WHILE,          word: "while"  },

	reserved{typ: TOKEN_ARGC,           word: "argc"   },
	reserved{typ: TOKEN_ARGV,           word: "argv"   },
	reserved{typ: TOKEN_BANG_EQUAL,     word: "!="     },
	reserved{typ: TOKEN_CONST,          word: "const"  },
	reserved{typ: TOKEN_EQUAL,          word: "="      },
	reserved{typ: TOKEN_FN,             word: "fn"     },
	reserved{typ: TOKEN_GREATER,        word: ">"      },
	reserved{typ: TOKEN_GREATER_EQUAL,  word: ">="     },
	reserved{typ: TOKEN_LEAVE,          word: "leave"  },
	reserved{typ: TOKEN_LESS,           word: "<"      },
	reserved{typ: TOKEN_LESS_EQUAL,     word: "<="     },
	reserved{typ: TOKEN_MINUS,          word: "-"      },
	reserved{typ: TOKEN_PERCENT,        word: "%"      },
	reserved{typ: TOKEN_PLUS,           word: "+"      },
	reserved{typ: TOKEN_RET,            word: "ret"    },
	reserved{typ: TOKEN_RIGHT_ARROW,    word: "->"     },
	reserved{typ: TOKEN_SLASH,          word: "/"      },
	reserved{typ: TOKEN_STAR,           word: "*"      },
	reserved{typ: TOKEN_THIS,           word: "this"   },
	reserved{typ: TOKEN_USING,          word: "using"  },
	reserved{typ: TOKEN_VAR,            word: "var"    },
}

type Location struct {
	f string
	c int
	l int
}

type Token struct {
	typ   TokenType
	loc   Location
	value any
}

type Scanner struct {
	filename string
	source   string
	column   int
	line     int
	tokens   []Token
}

var scanner Scanner

func makeToken(t TokenType, value ...any) {
	var token Token
	token.typ = t
	token.loc = Location{
		f: GetRelativePath(scanner.filename),
		c: scanner.column,
		l: scanner.line,
	}

	if value != nil {
		token.value = value[0]
	}

	scanner.tokens = append(scanner.tokens, token)
}

func makeReservedToken(word string) bool {
	for _, reserved := range reservedWords {
		if reserved.word == word {
			makeToken(reserved.typ)
			return true
		}
	}

	return false
}

// TODO: Find a better name for this function. Since I want to allow things like "2dup",
// I need this function to be able to post a WORD token if the number is followed by
// alpha characters.
func makeNumber(c byte, line string, index *int) {
	result := string(c)

	for Advance(&c, line, index) && IsDigit(c) {
		result += string(c)
	}

	if !IsSpace(c) && !IsReservedCharacter(c) {
		result += string(c)

		for Advance(&c, line, index) && !IsSpace(c) && !IsReservedCharacter(c) {
			result += string(c)
		}

		if !makeReservedToken(result) {
			makeToken(TOKEN_WORD, result)
		}

		return
	}

	value, _ := strconv.Atoi(result)
	makeToken(TOKEN_CONSTANT_INT, value)
}

func makeString(c byte, line string, index *int) {
	result := ""

	for Advance(&c, line, index) && c != '"' {
		if c == '\\' {
			Advance(&c, line, index)
			switch c {
			case '"': result += string(34)
			default: result += "\\" + string(c)
			}
		} else {
			result += string(c)
		}
	}

	makeToken(TOKEN_CONSTANT_STR, result)
}

func makeChar(c byte, line string, index *int) {
	var result byte
	Advance(&c, line, index)

	if (c == '\'') {
		loc := Location{f: scanner.filename, c: scanner.column, l: scanner.line}
		ReportErrorAtLocation(MsgParseInvalidEmptyCharacter, loc)
		ExitWithError(CodeParseError)
	} else if (c == '\\') {
		Advance(&c, line, index)
		switch c {
		case '0': result = 0
		case 'e': result = 27
		case 'n': result = 10
		case 'r': result = 13
		case 't': result = 9
		case 'v': result = 11
		}
	} else {
		result = c
	}

	Advance(&c, line, index)

	if (c != '\'') {
		loc := Location{f: scanner.filename, c: scanner.column, l: scanner.line}
		ReportErrorAtLocation(MsgParseInvalidCharacter, loc)
		ExitWithError(CodeParseError)
	}

	makeToken(TOKEN_CONSTANT_CHAR, result)
}

func makeWord(c byte, line string, index *int) {
	var typ TokenType
	var word string

	if c == '&' {
		typ = TOKEN_AMPERSAND
		word = ""
	} else {
		typ = TOKEN_WORD
		word = string(c)
	}

	for AdvanceWithChecks(&c, line, index) {
		word += string(c)
	}


	if !makeReservedToken(word) {
		makeToken(typ, word)
	}
}

func makeParapolyToken(c byte, line string, index *int) {
	word := ""

	for Advance(&c, line, index) && !IsSpace(c) {
		word += string(c)
	}

	makeToken(TOKEN_PARAPOLY, word)
}

func TokenizeFile(f string, s string) []Token {
	scanner.filename = f
	scanner.source = s
	scanner.column = 0
	scanner.line = 1
	scanner.tokens = make([]Token, 0, 32)

	b := bufio.NewScanner(strings.NewReader(scanner.source))
	b.Split(bufio.ScanLines)

	for b.Scan() {
		line := b.Text()

		for index := 0; index < len(line); index++ {
			c := line[index]
			scanner.column = index
			if (IsSpace(c)) {
				continue
			}

			switch {
			case c == '{': makeToken(TOKEN_CURLY_BRACKET_OPEN)
			case c == '}': makeToken(TOKEN_CURLY_BRACKET_CLOSE)
			case c == '[': makeToken(TOKEN_BRACKET_OPEN)
			case c == ']': makeToken(TOKEN_BRACKET_CLOSE)
			case c == '(': makeToken(TOKEN_PAREN_OPEN)
			case c == ')': makeToken(TOKEN_PAREN_CLOSE)
			case c == '&': makeWord(c, line, &index)
			case c == '$':
				makeParapolyToken(c, line, &index)
			case c == '"':
				makeString(c, line, &index)
			case c == '\'':
				makeChar(c, line, &index)
			case IsDigit(c):
				makeNumber(c, line, &index)
			default:
				makeWord(c, line, &index)
			}
		}

		scanner.line++
		scanner.column = 0
	}

	makeToken(TOKEN_EOF)

	return scanner.tokens
}
