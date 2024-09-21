package main

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:unicode"
import "core:unicode/utf8"

Tokenizer :: struct {
    column: int,
    filename: string,
    line: int,
    line_length: int,
    files: [dynamic]string,
}

Token :: struct {
    location: Location,
    type: Token_Type,
    value: Value,
}

Token_Type :: enum {
    // The Unknown token is a token that naturally ends with an error.
    // This is because the parser can't figure out what the token means.
    // It should really be a very strange error.
    UNKNOWN,

    // Custom word used by the user that doesn't match any native or intrinsic value
    WORD,

    // Intrinsics from the language
    PAREN_LEFT,
    PAREN_RIGHT,
    EOF,
    FUNCTION,
    MINUS,
    PERCENT,
    PLUS,
    PRINT,
    RETURNS,
    SLASH,
    STAR,
    TYPE_ANY,
    TYPE_BOOL,
    TYPE_FLOAT,
    TYPE_INT,
    TYPE_PTR,
    TYPE_STR,

    // Constants in the code parsing
    CONSTANT_FALSE,
    CONSTANT_FLOAT,
    CONSTANT_INT,
    CONSTANT_STRING,
    CONSTANT_TRUE,
}

Location :: struct {
    column: int,
    filename: string,
    line: int,
}

Reserved_Word :: struct {
    type: Token_Type,
    value: string,
}

reserved_words :: []Reserved_Word{
    { type = .PAREN_LEFT,     value = "(",     },
    { type = .PAREN_RIGHT,    value = ")",     },
    { type = .CONSTANT_FALSE, value = "false", },
    { type = .CONSTANT_TRUE,  value = "true",  },
    { type = .FUNCTION,       value = "fn",    },
    { type = .MINUS,          value = "-",     },
    { type = .PERCENT,        value = "%",     },
    { type = .PLUS,           value = "+",     },
    { type = .PRINT,          value = "print", },
    { type = .RETURNS,        value = "->",    },
    { type = .SLASH,          value = "/",     },
    { type = .STAR,           value = "*",     },
    { type = .TYPE_ANY,       value = "any",   },
    { type = .TYPE_BOOL,      value = "bool",  },
    { type = .TYPE_FLOAT,     value = "float", },
    { type = .TYPE_INT,       value = "int",   },
    { type = .TYPE_PTR,       value = "ptr",   },
    { type = .TYPE_STR,       value = "str",   },
}

USING_WORD :: "using"

tokenizer: Tokenizer

open_and_read_directories :: proc(dir: string) {
    fd, derr := os.open(dir)

    if derr != os.ERROR_NONE {
        error_at_tokenizer("TOKENIZER__CANNOT_OPEN_DIR", dir, derr)
    }

    fi, ierr := os.read_dir(fd, 0)

    if ierr != os.ERROR_NONE {
        error_at_tokenizer("TOKENIZER__CANNOT_READ_DIR", dir, ierr)
    }

    for f in fi {
        if f.is_dir {
            open_and_read_directories(f.fullpath)
        } else {
            if strings.has_suffix(f.name, ".sk") {
                append(&tokenizer.files, f.fullpath)
            }
        }
    }
}

tokenizer_run :: proc() {
    tokenizer.files = make([dynamic]string, 0, 2)

    if cargs.entry_type == .FILE {
        if os.is_file(cargs.entry) {
            append(&tokenizer.files, cargs.entry)
        } else {
            error_at_tokenizer("TOKENIZER__NOT_A_FILE", cargs.entry)
        }
    } else {
        if os.is_dir(cargs.entry) {
            open_and_read_directories(cargs.entry)
        } else {
            error_at_tokenizer("TOKENIZER__NOT_A_DIR", cargs.entry)
        }
    }

    if len(tokenizer.files) == 0 {
        error_at_tokenizer("TOKENIZER__NO_FILES_FOUND", cargs.entry)
    }

    for filename in tokenizer.files {
        tokenizer.filename = filename
        tokenizer.line = 1
        tokenizer.column = 0

        tokenize_file(filename)
    }

    make_eof_token()
}

tokenize_file :: proc(filename: string) {
    data, ok := os.read_entire_file(filename)
    defer delete(data)

    if !ok {
        error_at_tokenizer("TOKENIZER__CANNOT_OPEN_FILE", filename)
    }

    it := string(data)

    for line in strings.split_lines_iterator(&it) {
        tokenizer.column = 0
        tokenizer.line_length = len(line)

        for tokenizer.column < tokenizer.line_length {
            c := rune(line[tokenizer.column])

            if c == ';' {
                break
            }

            if c == ' ' {
                advance()
                continue
            }

            switch {
            case unicode.is_number(c): make_number_token(c, line)
            case c == '"': make_string_token(c, line)
            case: make_word_token(c, line)
            }

            advance()
        }

        tokenizer.line += 1
    }
}

advance :: proc() -> bool {
    tokenizer.column += 1

    if tokenizer.column >= tokenizer.line_length {
        return false
    }

    return true
}

make_word_token :: proc(c: rune, line: string) {
    token: Token
    result: [dynamic]rune
    defer delete(result)

    token.location = get_location()

    append(&result, c)

    for advance() {
        new_c := rune(line[tokenizer.column])

        if new_c == ' ' {
            break
        }

        append(&result, new_c)
    }

    val := utf8.runes_to_string(result[:])

    if val == USING_WORD {
        using_statement(line)
        return
    }

    for word in reserved_words {
        if word.value == val {
            token.type = word.type
        }
    }

    if token.type == .UNKNOWN {
        token.type = .WORD
        token.value = val
    }

    append(&program.tokens, token)
}

make_string_token :: proc(c: rune, line: string) {
    token: Token
    result: [dynamic]rune
    defer delete(result)

    token.location = get_location()
    token.type = .CONSTANT_STRING

    append(&result, c)

    for advance() {
        new_c := rune(line[tokenizer.column])

        append(&result, new_c)

        if new_c == '"' {
            break
        }
    }

    token.value = utf8.runes_to_string(result[:])

    append(&program.tokens, token)
}

make_number_token :: proc(c: rune, line: string) {
    token: Token
    result: [dynamic]rune
    defer delete(result)

    token.location = get_location()
    token.type = .CONSTANT_INT

    append(&result, c)

    for advance() {
        new_c := rune(line[tokenizer.column])

        if unicode.is_number(new_c) {
            append(&result, new_c)
        } else if new_c == '.' {
            append(&result, new_c)
            token.type = .CONSTANT_FLOAT
        } else if new_c == '_' {
            continue
        } else {
            break
        }
    }

    #partial switch token.type {
    case .CONSTANT_FLOAT:
        token.value = strconv.atof(utf8.runes_to_string(result[:]))
    case .CONSTANT_INT:
        token.value = strconv.atoi(utf8.runes_to_string(result[:]))
    }

    append(&program.tokens, token)
}

make_eof_token :: proc() {
    token: Token

    token.location = get_location()
    token.type = .EOF

    append(&program.tokens, token)
}

get_location :: proc() -> Location {
    return Location{
        line     = tokenizer.line,
        column   = tokenizer.column,
        filename = tokenizer.filename,
    }
}

using_statement :: proc(line: string) {
    lib_folder := strings.concatenate({ os.get_env("SKC_HOME"), "libs", })
    result: [dynamic]rune

    for advance() {
        c := rune(line[tokenizer.column])

        if unicode.is_alpha(c) {
            append(&result, c)
        }

        if c == ';' {
            break
        }
    }

    val := utf8.runes_to_string(result[:])
    filename := strings.concatenate({ val, ".sk", })

    append(&tokenizer.files, strings.concatenate({ lib_folder, "\\", filename, }))
}
