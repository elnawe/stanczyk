package skc

import (
	"bufio"
	"fmt"
	"os"
)

type OutputCode struct {
	code     []string
	data     []string
	metadata []string
}

func (this *OutputCode) WriteCode(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.code = append(this.code, newLine)
}

func (this *OutputCode) WriteData(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.data = append(this.data, newLine)
}

func (this *OutputCode) WriteMetadata(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.metadata = append(this.metadata, newLine)
}

func OutputRun(asm OutputCode) {
	//f, err := os.Create(Stanczyk.workspace.pDir + "/" + Stanczyk.workspace.out + ".asm")
	f, err := os.Create("output.asm")
	CheckError(err, "output.go-1")
	defer f.Close()

	b := bufio.NewWriter(f)

	for _, line := range asm.metadata {
		f.WriteString(line)
	}

	f.WriteString("\n")

	for _, line := range asm.data {
		f.WriteString(line)
	}

	f.WriteString("\n")

	for _, line := range asm.code {
		f.WriteString(line)
	}


	b.Flush()
}
