package skc

import (
	"fmt"
	"os/exec"
	"strings"
)

func BackendRun() {
	compilerArgs := strings.Split("-f elf64 -g output.asm", " ")
	linkerArgs := strings.Split("-o output output.o -m elf_x86_64", " ")

	_, err := exec.Command("nasm", compilerArgs...).Output()
	CheckError(err, "backend.go-1")
	_, err = exec.Command("ld", linkerArgs...).Output()
	CheckError(err, "backend.go-2")

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
