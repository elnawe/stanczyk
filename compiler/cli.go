package skc

import (
	"fmt"
	"os"
)

type CLIOptions struct {
	// clean: Removes all compilation files, like the Assembly output
	// and the Object file output.
	clean  bool

	// debug: Sets debug flags when linking to the system, providing a
	// way to debug the output through gdb and other debug tools.
	debug  bool

	// run: Run the final executable. If given during a 'build'
	// compilation, runs the result.  During a 'run' compilation
	// process, the run flag is always true.
	run    bool

	// silent: Hides all the output messages from the compiler (only
	// when the compilation is success).  This includes information
	// messages and timers of compilation.
	silent bool
}

type CLIWorkspace struct {
	// entry: The entry file. If a folder is given, it will be the
	// 'main.sk' on said folder.  * given by the user.
	entry string

	// out: The output filename. Name is used in the assembly output and
	// the final executable.  * given by the user.
	out   string

	// cDir: Folder where the compiler lives. Used to look up Stańczyk
	// libraries.  i.e. using "io" * computed by the compiler.
	cDir  string

	// pDir: Folder where the entry file is. Used to look up the file
	// system when needed, i.e. using "my/file.sk".  * computed by the
	// compiler.
	pDir  string
}

type CLI struct {
	// options: Compiler options given by the user. Change how the
	// compiler behaves or what it does during and after the compilation
	// process.
	options   CLIOptions

	// workspace: List of constants used throughout the compiling
    // process to find files, check which one to compile and build the
    // executable.
	workspace CLIWorkspace

	// ready: flag that marks the start of the compilation procress.
	ready     bool
}

func logo() {
	logo := `
███████╗████████╗ █████╗ ███╗   ██╗ ██████╗███████╗██╗   ██╗██╗  ██╗
██╔════╝╚══██╔══╝██╔══██╗████╗  ██║██╔════╝╚══███╔╝╚██╗ ██╔╝██║ ██╔╝
███████╗   ██║   ███████║██╔██╗ ██║██║       ███╔╝  ╚████╔╝ █████╔╝
╚════██║   ██║   ██╔══██║██║╚██╗██║██║      ███╔╝    ╚██╔╝  ██╔═██╗
███████║   ██║   ██║  ██║██║ ╚████║╚██████╗███████╗   ██║   ██║  ██╗
╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝
                                               The Stańczyk Compiler`
	fmt.Printf("\033[31m%s\n\033[0m", logo)
}

func (this *CLI) Error(e string, val ...any) {
	errorMessage := fmt.Sprintf(e, val...)

	fmt.Fprintf(os.Stderr, "ERROR: %s\n", errorMessage)
	this.Welcome()
	ExitWithError(CodeCliError)
}

func (this *CLI) Help() {
	// TODO: Add help messages
	logo()
}

func (this *CLI) Message(e string, val ...any) {
	if (!this.options.silent) {
		msg := fmt.Sprintf(e, val...)
		fmt.Fprintf(os.Stdout, "%s", msg)
	}
}

func (this *CLI) Welcome() {
	logo()
    fmt.Fprintf(os.Stderr, MsgCliWelcome)
	ExitWithError(CodeCliError)
}
