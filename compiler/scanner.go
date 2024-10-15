package skc

import (
	"bufio"
	"strconv"
	"strings"
)

type TokenType int

const (
	// CONSTANTS
	TOKEN_CONSTANT_BYTE TokenType = iota
	TOKEN_CONSTANT_FALSE
	TOKEN_CONSTANT_INT
	TOKEN_CONSTANT_STR
	TOKEN_CONSTANT_TRUE

	// Types
	TOKEN_ANY
	TOKEN_BOOL
	TOKEN_STARBOOL
	TOKEN_BYTE
	TOKEN_STARBYTE
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
	TOKEN_ELSE
	TOKEN_IF
	TOKEN_FI
	TOKEN_LOOP
	TOKEN_UNTIL
	TOKEN_WHILE

	TOKEN_BANG
	TOKEN_BANG_BYTE
	TOKEN_AT
	TOKEN_AT_BYTE

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
	TOKEN_DOT_DOT_DOT
	TOKEN_EQUAL
	TOKEN_FN
	TOKEN_FOREIGN
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
	kind TokenType
	word string
}

var reservedWords = []reserved{
	// CONSTANTS
	reserved{kind: TOKEN_CONSTANT_FALSE, word: "false"   },
	reserved{kind: TOKEN_CONSTANT_TRUE,  word: "true"    },

	// DATA TYPES
	reserved{kind: TOKEN_ANY,            word: "any"     },
	reserved{kind: TOKEN_BOOL,           word: "bool"    },
	reserved{kind: TOKEN_STARBOOL,       word: "*bool"   },
	reserved{kind: TOKEN_BYTE,           word: "byte"    },
	reserved{kind: TOKEN_STARBYTE,       word: "*byte"   },
	reserved{kind: TOKEN_INT,            word: "int"     },
	reserved{kind: TOKEN_STARINT,        word: "*int"    },
	reserved{kind: TOKEN_PTR,            word: "ptr"     },
	reserved{kind: TOKEN_STR,            word: "str"     },
	reserved{kind: TOKEN_STARSTR,        word: "*str"    },

	// MACROS
	reserved{kind: TOKEN_ASM,            word: "ASM"     },
	reserved{kind: TOKEN_AT_BODY,        word: "@body"   },

	reserved{kind: TOKEN_DASH_DASH_DASH, word: "---"     },
	reserved{kind: TOKEN_LET,            word: "let"     },
	reserved{kind: TOKEN_IN,             word: "in"      },
	reserved{kind: TOKEN_DONE,           word: "done"    },

	reserved{kind: TOKEN_BANG,           word: "!"       },
	reserved{kind: TOKEN_AT,             word: "@"       },
	reserved{kind: TOKEN_BANG_BYTE,      word: "!b"      },
	reserved{kind: TOKEN_AT_BYTE,        word: "@b"      },

	reserved{kind: TOKEN_ELSE,           word: "else"    },
	reserved{kind: TOKEN_FI,             word: "fi"      },
	reserved{kind: TOKEN_IF,             word: "if"      },
	reserved{kind: TOKEN_LOOP,           word: "loop"    },
	reserved{kind: TOKEN_UNTIL,          word: "until"   },
	reserved{kind: TOKEN_WHILE,          word: "while"   },

	reserved{kind: TOKEN_ARGC,           word: "argc"    },
	reserved{kind: TOKEN_ARGV,           word: "argv"    },
	reserved{kind: TOKEN_BANG_EQUAL,     word: "!="      },
	reserved{kind: TOKEN_CONST,          word: "const"   },
	reserved{kind: TOKEN_DOT_DOT_DOT,    word: "..."     },
	reserved{kind: TOKEN_EQUAL,          word: "="       },
	reserved{kind: TOKEN_FN,             word: "fn"      },
	reserved{kind: TOKEN_FOREIGN,        word: "foreign" },
	reserved{kind: TOKEN_GREATER,        word: ">"       },
	reserved{kind: TOKEN_GREATER_EQUAL,  word: ">="      },
	reserved{kind: TOKEN_LEAVE,          word: "leave"   },
	reserved{kind: TOKEN_LESS,           word: "<"       },
	reserved{kind: TOKEN_LESS_EQUAL,     word: "<="      },
	reserved{kind: TOKEN_MINUS,          word: "-"       },
	reserved{kind: TOKEN_PERCENT,        word: "%"       },
	reserved{kind: TOKEN_PLUS,           word: "+"       },
	reserved{kind: TOKEN_RET,            word: "ret"     },
	reserved{kind: TOKEN_RIGHT_ARROW,    word: "->"      },
	reserved{kind: TOKEN_SLASH,          word: "/"       },
	reserved{kind: TOKEN_STAR,           word: "*"       },
	reserved{kind: TOKEN_THIS,           word: "this"    },
	reserved{kind: TOKEN_USING,          word: "using"   },
	reserved{kind: TOKEN_VAR,            word: "var"     },
}

type Location struct {
	f string
	c int
	l int
}

type Token struct {
	kind   TokenType
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
	token.kind = t
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
			makeToken(reserved.kind)
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

	makeToken(TOKEN_CONSTANT_BYTE, result)
}

func makeWord(c byte, line string, index *int) {
	var kind TokenType
	var word string

	if c == '&' {
		kind = TOKEN_AMPERSAND
		word = ""
	} else {
		kind = TOKEN_WORD
		word = string(c)
	}

	for AdvanceWithChecks(&c, line, index) {
		word += string(c)
	}


	if !makeReservedToken(word) {
		makeToken(kind, word)
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
