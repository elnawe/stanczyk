package main

import "core:c/libc"
import "core:os"
import "core:strings"

compile_run :: proc() {
    exec := strings.concatenate({
        "odin ", cargs.command,
        " ", cargs.odin_file,
        " -file -out:", cargs.out,
    })

    libc.system(strings.clone_to_cstring(exec))

    os.remove(cargs.odin_file)

    if cargs.command == "run" {
        os.remove(cargs.out)
    }
}
