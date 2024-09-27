package skc

import (
	"fmt"
)

type Assembly struct {
	bss    []string
	data   []string
	rodata []string
	text   []string
}


func (this *Assembly) WriteBss(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.bss = append(this.bss, newLine)
}

func (this *Assembly) WriteData(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.data = append(this.data, newLine)
}

func (this *Assembly) WriteRodata(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.text = append(this.rodata, newLine)
}

func (this *Assembly) WriteText(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.text = append(this.text, newLine)
}
