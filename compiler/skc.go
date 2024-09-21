package skc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const CompilerVersion = "0.3"

var Stanczyk CLI

// TODO: This is basically panicking out of the execution, I need to properly handle this error differently
func CheckError(e error, s string) {
	if e != nil {
		Stanczyk.Error(TodoRemoveCliCannotGetDirectory, s, e.Error())
	}
}

func parseArguments() {
	args := os.Args[2:]

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case strings.Contains(arg, ".sk"):
			Stanczyk.workspace.entry = arg
		case arg == "-o", arg == "-out":
			i++
			arg = args[i]
			Stanczyk.workspace.out = arg
		case arg == "-C", arg == "-clean":
			Stanczyk.options.clean = true
		case arg == "-d", arg == "-debug":
			Stanczyk.options.debug = true
		case arg == "-r", arg == "-run":
			Stanczyk.options.run = true
		case arg == "-s", arg == "-silent":
			Stanczyk.options.silent = true
		default:
			Stanczyk.Error(MsgCliUnknownArgument, arg)
		}
	}
}

func parseCommand() {
	command := os.Args[1]

	switch command {
	case "run":
		Stanczyk.options.run = true
		Stanczyk.options.clean = true
		Stanczyk.options.silent = true
	case "build":
		Stanczyk.options.debug = false
	case "help":
		Stanczyk.Help()
	default:
		Stanczyk.Error(MsgCliUnknownCommand, command)
	}
}

func setupWorkspace() {
	compilerExec := os.Args[0]
	eName, err := exec.LookPath(compilerExec)
	CheckError(err, "skc.go-1")
	cDir, err := filepath.Abs(eName)
	CheckError(err, "skc.go-2")

	Stanczyk.workspace.cDir = filepath.Dir(cDir)

	filename := "./" + Stanczyk.workspace.entry
	_, err = os.Stat(filename);
	CheckError(err, "skc.go-3")
	pDir, err := os.Getwd()
	CheckError(err, "skc.go-4")

	Stanczyk.workspace.pDir = pDir

	if Stanczyk.workspace.out == "" {
		out := Stanczyk.workspace.entry[:len(Stanczyk.workspace.entry) - 3]
		Stanczyk.workspace.out = out
	}
}

func Run() {
	if len(os.Args) < 2 {
		Stanczyk.Welcome()
	}

	parseCommand()
	parseArguments()
	setupWorkspace()

	RunTasks()
}
