package skc

import (
	"bufio"
	"fmt"
	"os"
)

type OutputCode struct {
	bss    []string
	data   []string
	rodata []string
	text   []string
}

func (this *OutputCode) WriteBss(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.bss = append(this.bss, newLine)
}

func (this *OutputCode) WriteData(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.data = append(this.data, newLine)
}

func (this *OutputCode) WriteRodata(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.text = append(this.rodata, newLine)
}

func (this *OutputCode) WriteText(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.text = append(this.text, newLine)
}

func OutputRun(asm OutputCode) {
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
