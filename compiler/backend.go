package skc

import (
	"fmt"
	"os/exec"
	"strings"
)

func BackendRun() {
	if TheProgram.libcEnabled {
		compilerArgs := strings.Split("-m 524288 output.asm output.o", " ")
		linkerArgs := strings.Split("-L. -no-pie -z noexecstack output.o -o output", " ")
		_, err := exec.Command("fasm", compilerArgs...).Output()
		CheckError(err, "backend.go-1")
		_, err = exec.Command("gcc", linkerArgs...).Output()
		CheckError(err, "backend.go-2")
	} else {
		compilerArgs := strings.Split("-m 524288 output.asm", " ")
		chmodArgs := strings.Split("+x output", " ")
		_, err := exec.Command("fasm", compilerArgs...).Output()
		CheckError(err, "backend.go-1")
		_, err = exec.Command("chmod", chmodArgs...).Output()
		CheckError(err, "backend.go-2")
	}

	if Stanczyk.options.clean {
		_, _ = exec.Command("rm", "output.o").Output()
		_, _ = exec.Command("rm", "output.asm").Output()
	}

	if Stanczyk.options.run {
		b := new(strings.Builder)
		cmd := exec.Command("./output")
		cmd.Stdout = b
		cmd.Run()
		fmt.Print(b.String())

		if Stanczyk.options.clean {
			_, _ = exec.Command("rm", "output").Output()
		}
	}
}
