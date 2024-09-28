package skc

import (
	"bufio"
	"os"
)

func OutputRun(asm Assembly) {
	//f, err := os.Create(Stanczyk.workspace.pDir + "/" + Stanczyk.workspace.out + ".asm")
	f, err := os.Create("output.asm")
	CheckError(err, "output.go-1")
	defer f.Close()

	b := bufio.NewWriter(f)

	for _, line := range asm.text {
		f.WriteString(line)
	}

	f.WriteString("\n")

	for _, line := range asm.data {
		f.WriteString(line)
	}

	f.WriteString("\n")

	for _, line := range asm.rodata {
		f.WriteString(line)
	}

	f.WriteString("\n")

	for _, line := range asm.bss {
		f.WriteString(line)
	}

	b.Flush()
}
