package main

import (
	"bufio"
	"strconv"
	"strings"
)

type TokenType int

const (
	// Constants
	TOKEN_INT TokenType = iota
	TOKEN_STR

	// Reserved Words
	TOKEN_BANG_EQUAL
	TOKEN_DIV
	TOKEN_DO
	TOKEN_DOT
	TOKEN_DROP
	TOKEN_EQUAL
	TOKEN_FALSE
	TOKEN_GREATER
	TOKEN_GREATER_EQUAL
	TOKEN_LESS
	TOKEN_LESS_EQUAL
	TOKEN_MACRO
	TOKEN_MINUS
	TOKEN_PLUS
	TOKEN_PRINT
	TOKEN_STAR
	TOKEN_SWAP
	TOKEN_SYSCALL3
	TOKEN_TRUE
	TOKEN_USING

	// Specials
	TOKEN_EOF
	TOKEN_WORD
)

type reserved struct {
	name string
	typ  TokenType
}

var reservedWords = [16]reserved{
	reserved{name: "+",         typ: TOKEN_PLUS},
	reserved{name: "-",         typ: TOKEN_MINUS},
	reserved{name: "*",         typ: TOKEN_STAR},
	reserved{name: ".",         typ: TOKEN_DOT},
	reserved{name: "=",         typ: TOKEN_EQUAL},
	reserved{name: "!=",        typ: TOKEN_BANG_EQUAL},
	reserved{name: "div",		typ: TOKEN_DIV},
	reserved{name: "do",		typ: TOKEN_DO},
	reserved{name: "drop",      typ: TOKEN_DROP},
	reserved{name: "false",		typ: TOKEN_FALSE},
	reserved{name: "macro",		typ: TOKEN_MACRO},
	reserved{name: "print",		typ: TOKEN_PRINT},
	reserved{name: "swap",      typ: TOKEN_SWAP},
	reserved{name: "syscall3",	typ: TOKEN_SYSCALL3},
	reserved{name: "true",		typ: TOKEN_TRUE},
	reserved{name: "using",		typ: TOKEN_USING},
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

func makeWord(c byte, line string, index *int) {
	word := string(c)

	for Advance(&c, line, index) && c != ' ' {
		word += string(c)
	}

	for _, reserved := range reservedWords {
		if reserved.name == word {
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
			if (c == ' ') {
				continue
			}

			switch {
			case c == '"':
				makeString(c, line, &index)
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