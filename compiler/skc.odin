package main

import "core:fmt"
import "core:log"
import "core:mem"
import "core:os"
import "core:slice"
import "core:strings"

SKC_VERSION :: "1"
SKC_DATE :: "2024-09-14"

Program :: struct {
    body: [dynamic]FunctionStatement,
    errors: [dynamic]string,
    compiler_errors: [dynamic]CompilerError,
    tokens: [dynamic]Token,
    main_fn_id: string,
}

DataType :: enum {
    ANY,
    BOOL,
    FLOAT,
    INT,
    STRING,
}

Value :: union { bool, f64, int, string, }

EntryTypeGiven :: enum { DIR, FILE, }

ErrorType :: enum {
    UNKNOWN,

    BLOCK_OF_CODE_CLOSURE_EXPECTED,
    FUNCTION_IDENTIFIER_ALREADY_EXISTS,
    FUNCTION_IDENTIFIER_IS_NOT_A_VALID_WORD,
    MISSING_IDENTIFIER_FOR_NUMERIC_CONSTANT,
    MISSING_STACK_VALUE_FOR_OPERATION,

    WORK_IN_PROGRESS,
}

CompilerError :: struct {
    error_type: ErrorType,
    token: Token,
}

Compiler_Args :: struct {
    entry: string,
    entry_type: enum { FILE, DIR, },
    out: string,
    odin_file: string,
    command: string,
    opts: struct {
        debug: bool,
    },
}

skc_valid_commands := []string{ "build", "run", "help", "version", }

cargs : Compiler_Args
program: Program

main :: proc() {
    when ODIN_DEBUG {
        // Setup compiler safe memory tracking allocator and logger
        context.logger = log.create_console_logger()

        default_alloc := context.allocator
        tracking_alloc : mem.Tracking_Allocator
        mem.tracking_allocator_init(&tracking_alloc, default_alloc)
        context.allocator = mem.tracking_allocator(&tracking_alloc)

        reset_tracking_allocator :: proc(a: ^mem.Tracking_Allocator) -> bool {
            err := false

            for _, value in a.allocation_map {
                fmt.println("ERROR::DEV_MODE")
                fmt.printfln("%v: Leaked %v bytes", value.location, value.size)
                err = true
            }

            mem.tracking_allocator_clear(a)

            return err
        }
    }

    // Stanczyk Compiler command order and usage
    // 0. skc                 :: The Compiler
    // 1. <command>           :: Output command (run/build/help)
    // 2. <file>.sk <folder>/ :: The entry file or folder
    // 3. --<arg>             :: Different arguments like linking libraries or configurations
    if len(os.args) < 2 {
        print_motd()
        return
    }

    cargs.command = os.args[1]

    if !slice.contains(skc_valid_commands[:], cargs.command) {
        print_invalid_command()
        return
    }

    switch cargs.command {
    case "help":
        print_help()
        return
    case "version":
        print_version()
        return
    }

    if len(os.args) < 3 {
        print_missing_file_or_directory()
        return
    }

    cargs.entry = os.args[2]
    cargs.entry_type = strings.has_suffix(cargs.entry, ".sk") ? .FILE : .DIR

    no_ext_name := strings.split(cargs.entry, ".")[0]
    cargs.odin_file = strings.concatenate({ no_ext_name, ".odin", })
    cargs.out = get_os_extension(no_ext_name)

    for index := 3; index < len(os.args); index += 1 {
        arg := os.args[index]

        switch {
        case strings.has_prefix(arg, "-out:"):
            outputs := strings.split(arg, ":")
            cargs.out = get_os_extension(outputs[1])
        case arg == "-debug":
            cargs.opts.debug = true
        }
    }

    start_compiling_process()
}

start_compiling_process :: proc() {
    program.tokens = make([dynamic]Token, 0, 32)
    program.body = make([dynamic]FunctionStatement, 0, 16)
    program.errors = make([dynamic]string, 0, 4)
    program.compiler_errors = make([dynamic]CompilerError, 0, 4)

    tokenizer_run()
    ast_run()
    codegen_run()
    compile_run()
}
