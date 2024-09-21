package skc

import (
	"fmt"
)

type Assembly struct {
	text []string
	data []string
	bss  []string
}

func (this *Assembly) WriteText(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.text = append(this.text, newLine)
}

func (this *Assembly) WriteData(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.data = append(this.data, newLine)
}

func (this *Assembly) WriteBss(s string, values ...any) {
	newLine := fmt.Sprintf(s + "\n", values...)
	this.bss = append(this.bss, newLine)
}
