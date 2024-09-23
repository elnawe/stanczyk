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
	TOKEN_DTYPE_BOOL
	TOKEN_DTYPE_CHAR
	TOKEN_DTYPE_INT
	TOKEN_DTYPE_PTR

	// Reserved Words
	TOKEN_ARGC
	TOKEN_ARGV
	TOKEN_BANG_EQUAL
	TOKEN_BIND
	TOKEN_CAST_BOOL
	TOKEN_CAST_CHAR
	TOKEN_CAST_INT
	TOKEN_CAST_PTR
	TOKEN_CONST
	TOKEN_DIV
	TOKEN_DROP
	TOKEN_DUP
	TOKEN_ELSE
	TOKEN_EQUAL
	TOKEN_EXTERN
	TOKEN_FN
	TOKEN_FN_STAR
	TOKEN_GREATER
	TOKEN_GREATER_EQUAL
	TOKEN_IF
	TOKEN_LESS
	TOKEN_LESS_EQUAL
	TOKEN_LOAD8
	TOKEN_LOAD16
	TOKEN_LOAD32
	TOKEN_LOAD64
	TOKEN_LOOP
	TOKEN_MINUS
	TOKEN_OVER
	TOKEN_PAREN_CLOSE
	TOKEN_PAREN_OPEN
	TOKEN_PLUS
	TOKEN_RESERVE
	TOKEN_RET
	TOKEN_RIGHT_ARROW
	TOKEN_ROTATE
	TOKEN_STAR
	TOKEN_STORE8
	TOKEN_STORE16
	TOKEN_STORE32
	TOKEN_STORE64
	TOKEN_SWAP
	TOKEN_TAKE
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
	reserved{typ: TOKEN_ARGC,           word: "argc"    },
	reserved{typ: TOKEN_ARGV,           word: "argv"    },
	reserved{typ: TOKEN_BANG_EQUAL,     word: "!="      },
	reserved{typ: TOKEN_BIND,           word: "bind"    },
	reserved{typ: TOKEN_CAST_BOOL,      word: "(bool)"  },
	reserved{typ: TOKEN_CAST_CHAR,      word: "(char)"  },
	reserved{typ: TOKEN_CAST_INT,       word: "(int)"   },
	reserved{typ: TOKEN_CAST_PTR,       word: "(ptr)"   },
	reserved{typ: TOKEN_CONST,          word: "const"   },
	reserved{typ: TOKEN_DIV,            word: "div"	    },
	reserved{typ: TOKEN_DROP,           word: "drop"    },
	reserved{typ: TOKEN_DTYPE_BOOL,     word: "bool"    },
	reserved{typ: TOKEN_DTYPE_CHAR,     word: "char"    },
	reserved{typ: TOKEN_DTYPE_INT,      word: "int"     },
	reserved{typ: TOKEN_DTYPE_PTR,      word: "ptr"     },
	reserved{typ: TOKEN_DUP,            word: "dup"     },
	reserved{typ: TOKEN_ELSE,           word: "else"    },
	reserved{typ: TOKEN_EQUAL,          word: "="       },
	reserved{typ: TOKEN_EXTERN,         word: "extern"  },
	reserved{typ: TOKEN_FALSE,          word: "false"   },
	reserved{typ: TOKEN_FN,             word: "fn"      },
	reserved{typ: TOKEN_FN_STAR,        word: "fn*"     },
	reserved{typ: TOKEN_GREATER,        word: ">"       },
	reserved{typ: TOKEN_GREATER_EQUAL,  word: ">="      },
	reserved{typ: TOKEN_IF,             word: "if"      },
	reserved{typ: TOKEN_LESS,           word: "<"       },
	reserved{typ: TOKEN_LESS_EQUAL,     word: "<="      },
	reserved{typ: TOKEN_LOAD8,          word: "->8"     },
	reserved{typ: TOKEN_LOAD16,         word: "->16"    },
	reserved{typ: TOKEN_LOAD32,         word: "->32"    },
	reserved{typ: TOKEN_LOAD64,         word: "->64"    },
	reserved{typ: TOKEN_LOOP,           word: "loop"    },
	reserved{typ: TOKEN_MINUS,          word: "-"       },
	reserved{typ: TOKEN_OVER,           word: "over"    },
	reserved{typ: TOKEN_PAREN_CLOSE,    word: ")"       },
	reserved{typ: TOKEN_PAREN_OPEN,     word: "("       },
	reserved{typ: TOKEN_PLUS,           word: "+"       },
	reserved{typ: TOKEN_RESERVE,        word: "reserve" },
	reserved{typ: TOKEN_RET,            word: "ret"     },
	reserved{typ: TOKEN_RIGHT_ARROW,    word: "->"      },
	reserved{typ: TOKEN_ROTATE,         word: "rotate"  },
	reserved{typ: TOKEN_STAR,           word: "*"       },
	reserved{typ: TOKEN_STORE8,         word: "<-8"     },
	reserved{typ: TOKEN_STORE16,        word: "<-16"    },
	reserved{typ: TOKEN_STORE32,        word: "<-32"    },
	reserved{typ: TOKEN_STORE64,        word: "<-64"    },
	reserved{typ: TOKEN_SWAP,           word: "swap"    },
	reserved{typ: TOKEN_TAKE,           word: "take"    },
	reserved{typ: TOKEN_THIS,           word: "this"    },
	reserved{typ: TOKEN_TRUE,           word: "true"    },
	reserved{typ: TOKEN_VAR,            word: "var"     },
	reserved{typ: TOKEN_USING,          word: "using"   },
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
		f: scanner.filename,
		c: scanner.column,
		l: scanner.line,
	}

	if value != nil {
		token.value = value[0]
	}

	scanner.tokens = append(scanner.tokens, token)
}

func makeNumber(c byte, line string, index *int) {
	result := string(c)

	for Advance(&c, line, index) && IsDigit(c) {
		result += string(c)
	}

	value, _ := strconv.Atoi(result)
	makeToken(TOKEN_INT, value)
}

func makeString(c byte, line string, index *int) {
	result := ""

	for Advance(&c, line, index) && c != '"' {
		result += string(c)
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

	for Advance(&c, line, index) && c != ' ' && c != '\t' {
		word += string(c)
	}

	for _, reserved := range reservedWords {
		if reserved.word == word {
			makeToken(reserved.typ)
			return
		}
	}

	makeToken(TOKEN_WORD, word)
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
			if (c == ' ' || c == '\t') {
				continue
			}

			switch {
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
