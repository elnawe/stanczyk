package main

import "core:fmt"
import "core:strings"

print_aligned :: proc(left, right: string) {
    fmt.printfln("\t{0}\t\t{1}", left, right)
}

print_title :: proc() {
    when ODIN_OS == .Windows {
        fmt.print("The Stanczyk Programming Language Compiler\n\n")
    }
}

print_motd :: proc() {
    print_title()

    fmt.println("Usage:")
    fmt.println("\tskc command <file/directory> [arguments]")
    fmt.println("Commands:")
    print_aligned("build", "Compiles the file or directory (specified after this command), and outputs an executable.")
    print_aligned("run", "Same as build, but it also executes the program after compiling.")
    print_aligned("help", "Prints this message and more helpful information")
    print_aligned("version", "Prints the current compiler version")
}

print_help :: proc() {
    print_motd()

    fmt.print("\n")
    fmt.println("How to use:")
    fmt.println("\tUse the compiler, the command and an entry file to compile an executable.")
    fmt.println("\tExample: skc run code.sk")
}

print_version :: proc() {
    print_title()
    fmt.printfln("skc version {0} ({1})", SKC_VERSION, SKC_DATE)
}

print_invalid_command :: proc() {
    print_title()
    fmt.printfln(
        "Command `{0}` is not a valid command. The available commands are: {1}.",
        cargs.command,
        strings.join(skc_valid_commands, ", "),
    )
}

print_missing_file_or_directory :: proc() {
    print_title()
    fmt.println("Missing file or directory after the command. Use `skc help` for more information.")
    fmt.printfln("Example: skc {0} code.sk", cargs.command)
}

print_all_compiler_errors :: proc() {
    print_title()

    fmt.println("Errors found at compilation:")

    for err in program.errors {
        fmt.printfln("\t- {0}", err)
    }
}
