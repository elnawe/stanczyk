package skc

import (
	"fmt"
	"os/exec"
	"strings"
)

func BackendRun() {
	compilerArgs := strings.Split("-m 524288 output.asm", " ")
	chmodArgs := strings.Split("+x output", " ")
	// linkerArgs := strings.Split("-o output output.o -m elf_x86_64", " ")

	_, err := exec.Command("fasm", compilerArgs...).Output()
	CheckError(err, "backend.go-1")
	_, err = exec.Command("chmod", chmodArgs...).Output()
	CheckError(err, "backend.go-2")
	// _, err = exec.Command("ld", linkerArgs...).Output()
	// CheckError(err, "backend.go-2")

	if Stanczyk.options.clean {
		_, err = exec.Command("rm", "output.o").Output()
		_, err = exec.Command("rm", "output.asm").Output()
	}

	if Stanczyk.options.run {
		b := new(strings.Builder)
		cmd := exec.Command("./output")
		cmd.Stdout = b
		cmd.Run()
		fmt.Print(b.String())

		if Stanczyk.options.clean {
			_, err = exec.Command("rm", "output").Output()
		}
	}
}
