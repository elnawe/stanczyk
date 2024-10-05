package skc

import (
	"bufio"
	"strconv"
	"strings"
)

type TokenType int

const (
	// Constants
	TOKEN_CHAR TokenType = iota
	TOKEN_FALSE
	TOKEN_INT
	TOKEN_STR
	TOKEN_TRUE

	// Types
	TOKEN_DTYPE_ANY
	TOKEN_DTYPE_BOOL
	TOKEN_DTYPE_CHAR
	TOKEN_DTYPE_INT
	TOKEN_DTYPE_PARAPOLY
	TOKEN_DTYPE_PTR

	// Flow Control
	TOKEN_CASE
	TOKEN_ELSE
	TOKEN_FOR // TODO: Remove
	TOKEN_IF
	TOKEN_FI
	TOKEN_LOOP
	TOKEN_UNTIL
	TOKEN_WHILE

	// Single characters
	TOKEN_BRACKET_CLOSE
	TOKEN_BRACKET_OPEN
	TOKEN_PAREN_CLOSE
	TOKEN_PAREN_OPEN

	// NEW
	TOKEN_DASH_DASH_DASH
	TOKEN_LET
	TOKEN_LETSTAR
	TOKEN_IN
	TOKEN_DONE

	// Reserved Words
	TOKEN_ARGC
	TOKEN_ARGV
	TOKEN_ASM
	TOKEN_BANG_EQUAL
	TOKEN_CONST
	TOKEN_EQUAL
	TOKEN_FN
	TOKEN_GREATER
	TOKEN_GREATER_EQUAL
	TOKEN_LEAVE
	TOKEN_LESS
	TOKEN_LESS_EQUAL
	TOKEN_LOAD8
	TOKEN_LOAD16
	TOKEN_LOAD32
	TOKEN_LOAD64
	TOKEN_MINUS
	TOKEN_PERCENT
	TOKEN_PLUS
	TOKEN_RET
	TOKEN_RIGHT_ARROW
	TOKEN_SLASH
	TOKEN_STAR
	TOKEN_STORE8
	TOKEN_STORE16
	TOKEN_STORE32
	TOKEN_STORE64
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
	reserved{typ: TOKEN_DASH_DASH_DASH, word: "---"    },
	reserved{typ: TOKEN_LET,            word: "let"    },
	reserved{typ: TOKEN_LETSTAR,        word: "let*"   },
	reserved{typ: TOKEN_IN,             word: "in"     },
	reserved{typ: TOKEN_DONE,           word: "done"   },

	reserved{typ: TOKEN_DTYPE_ANY,      word: "any"    },
	reserved{typ: TOKEN_DTYPE_BOOL,     word: "bool"   },
	reserved{typ: TOKEN_DTYPE_CHAR,     word: "char"   },
	reserved{typ: TOKEN_DTYPE_INT,      word: "int"    },
	reserved{typ: TOKEN_DTYPE_PTR,      word: "ptr"    },

	reserved{typ: TOKEN_FI,             word: "fi"     },
	reserved{typ: TOKEN_FOR,            word: "for"    },
	reserved{typ: TOKEN_IF,             word: "if"     },
	reserved{typ: TOKEN_LOOP,           word: "loop"   },
	reserved{typ: TOKEN_UNTIL,          word: "until"  },
	reserved{typ: TOKEN_WHILE,          word: "while"  },

	reserved{typ: TOKEN_ARGC,           word: "argc"   },
	reserved{typ: TOKEN_ARGV,           word: "argv"   },
	reserved{typ: TOKEN_ASM,            word: "asm"    },
	reserved{typ: TOKEN_BANG_EQUAL,     word: "!="     },
	reserved{typ: TOKEN_CONST,          word: "const"  },
	reserved{typ: TOKEN_ELSE,           word: "else"   },
	reserved{typ: TOKEN_EQUAL,          word: "="      },
	reserved{typ: TOKEN_FALSE,          word: "false"  },
	reserved{typ: TOKEN_FN,             word: "fn"     },
	reserved{typ: TOKEN_GREATER,        word: ">"      },
	reserved{typ: TOKEN_GREATER_EQUAL,  word: ">="     },
	reserved{typ: TOKEN_LEAVE,          word: "leave"  },
	reserved{typ: TOKEN_LESS,           word: "<"      },
	reserved{typ: TOKEN_LESS_EQUAL,     word: "<="     },
	reserved{typ: TOKEN_LOAD8,          word: "->8"    },
	reserved{typ: TOKEN_LOAD16,         word: "->16"   },
	reserved{typ: TOKEN_LOAD32,         word: "->32"   },
	reserved{typ: TOKEN_LOAD64,         word: "->64"   },
	reserved{typ: TOKEN_MINUS,          word: "-"      },
	reserved{typ: TOKEN_PERCENT,        word: "%"      },
	reserved{typ: TOKEN_PLUS,           word: "+"      },
	reserved{typ: TOKEN_RET,            word: "ret"    },
	reserved{typ: TOKEN_RIGHT_ARROW,    word: "->"     },
	reserved{typ: TOKEN_SLASH,          word: "/"      },
	reserved{typ: TOKEN_STAR,           word: "*"      },
	reserved{typ: TOKEN_STORE8,         word: "<-8"    },
	reserved{typ: TOKEN_STORE16,        word: "<-16"   },
	reserved{typ: TOKEN_STORE32,        word: "<-32"   },
	reserved{typ: TOKEN_STORE64,        word: "<-64"   },
	reserved{typ: TOKEN_THIS,           word: "this"   },
	reserved{typ: TOKEN_TRUE,           word: "true"   },
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
	makeToken(TOKEN_INT, value)
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

	makeToken(TOKEN_STR, result)
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

	makeToken(TOKEN_CHAR, result)
}

func makeWord(c byte, line string, index *int) {
	word := string(c)

	for AdvanceWithChecks(&c, line, index) {
		word += string(c)
	}

	if !makeReservedToken(word) {
		makeToken(TOKEN_WORD, word)
	}
}

func makeParapolyToken(c byte, line string, index *int) {
	word := ""

	for Advance(&c, line, index) && !IsSpace(c) {
		word += string(c)
	}

	makeToken(TOKEN_DTYPE_PARAPOLY, word)
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
			case c == '[': makeToken(TOKEN_BRACKET_OPEN)
			case c == ']': makeToken(TOKEN_BRACKET_CLOSE)
			case c == '(': makeToken(TOKEN_PAREN_OPEN)
			case c == ')': makeToken(TOKEN_PAREN_CLOSE)
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
