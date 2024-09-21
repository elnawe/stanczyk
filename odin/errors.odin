package main

import "core:fmt"
import "core:os"

Panic_Error_Code :: enum {
    NONE = 0,
    PARSER,
    AST,
}

errors := map[string]string{
    "AST__BODY__FUNCTION_DECLARATION_NOT_ALLOWED" = "Function declaration not allowed in the current scope.",
    "AST__BODY__INCORRECT_STACK_VALUE_TYPES" = "Function call with incorrect value types.",
    "AST__BODY__MISSING_STACK_VALUES_EXPECTED_GOT" = "Missing stack value(s). Expected: {0} but got {1}.",
    "AST__BODY__STACK_NOT_EMPTY" = "Stack is not empty by the end of the function declaration.",
    "AST__FUNCTION__MISSING_CLOSING_STATEMENT" = "End of file encountered before closing function declaration.",
    "AST__FUNCTION__IDENTIFIER_EXISTS" = "Can't override identifier {0}. Another function or variable with the same name exists in this context.",
    "AST__FUNCTION__IDENTIFIER_IS_NOT_A_VALID_WORD" = "Identifier used in this function is not a valid word. Identifiers should begin with an alphabetic character or a symbol.",
    "AST__GLOBAL__INVALID_SCOPE" = "Only declarations can be done on the global scope.",
    "AST__MAIN__NO_ARGUMENTS_OR_RETURNS_ALLOWED" = "Function declaration for `main` should not have argument or return values.",

    "GENERAL__COMPILER_BUG" = "This is an error that you found that might be just a compiler error, and it should've never happened. Please, report it at https://github.com/nawetimebomb/stanczyk.",

    "TOKENIZER__CANNOT_OPEN_DIR" = "Can't open directory `{0}`. Error: {1}",
    "TOKENIZER__CANNOT_OPEN_FILE" = "Can't open file `{0}`.",
    "TOKENIZER__CANNOT_READ_DIR" = "Can't read directory `{0}`. Error: {1}",
    "TOKENIZER__NO_FILES_FOUND" = "No files found on directory `{0}`.",
    "TOKENIZER__NOT_A_DIR" = "Directory `{0}` not found.",
    "TOKENIZER__NOT_A_FILE" = "File `{0}` not found or is not an actual file.",
}

// This is only used when the error on one of the steps of the compilation is too hard to handle.
// Usually, I don't want to panic the execution so the user knows of all the possible errors on
// their code and can fix them at once, but if the error could break the whole compilation, then
// it's safer to just panic out.
panic_execution :: proc(ecode: Panic_Error_Code) {
    code := int(ecode)
    print_all_compiler_errors()
    fmt.printfln("\nExited with error code {0}", code)
    os.exit(code)
}

error_at_ast :: proc(t: Token, err_key: string, rest: ..any) {
    loc := t.location
    err_msg := get_error_message(err_key, ..rest)
    full_msg := fmt.aprintf(
        "{0}:{1}:{2}: {3}",
        loc.filename, loc.line, loc.column, err_msg,
    )
    append(&program.errors, full_msg)
}

error_at_tokenizer :: proc(err_key: string, rest: ..any) {
    err_msg := get_error_message(err_key, ..rest)
    append(&program.errors, err_msg)
    panic_execution(.PARSER)
}

get_error_message :: proc(err: string, rest: ..any) -> string {
    return fmt.aprintf(errors[err], ..rest)
}
