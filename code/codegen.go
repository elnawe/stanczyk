package main

import (
	"fmt"
	"runtime"
)

type Codegen struct {
	chunk Chunk
	asm *Assembly
}

var codegen Codegen

func getAsciiValues(s string) (string, int) {
	count := 0
	nextEscaped := false
	ascii := ""

	for _, c := range s {
		if c == '\\' {
			nextEscaped = true
			continue
		}

		if nextEscaped {
			switch c {
			case 't':
				ascii += "9,"
				count++
			case 'n':
				ascii += "10,"
				count++
			}

			nextEscaped = false
			continue
		}

		val := fmt.Sprintf("%v,", c)
		ascii += val
		count++
	}

	return ascii, count
}

func generateLinuxX86() {
	asm := codegen.asm

	asm.WriteText("section .text")
    asm.WriteText("global _start")
    asm.WriteText("print:")
    asm.WriteText("    mov     r9, -3689348814741910323")
    asm.WriteText("    sub     rsp, 40")
    asm.WriteText("    mov     BYTE [rsp+31], 10")
    asm.WriteText("    lea     rcx, [rsp+30]")
    asm.WriteText(".L2:")
    asm.WriteText("    mov     rax, rdi")
    asm.WriteText("    lea     r8, [rsp+32]")
    asm.WriteText("    mul     r9")
    asm.WriteText("    mov     rax, rdi")
    asm.WriteText("    sub     r8, rcx")
    asm.WriteText("    shr     rdx, 3")
    asm.WriteText("    lea     rsi, [rdx+rdx*4]")
    asm.WriteText("    add     rsi, rsi")
    asm.WriteText("    sub     rax, rsi")
    asm.WriteText("    add     eax, 48")
    asm.WriteText("    mov     BYTE [rcx], al")
    asm.WriteText("    mov     rax, rdi")
    asm.WriteText("    mov     rdi, rdx")
    asm.WriteText("    mov     rdx, rcx")
    asm.WriteText("    sub     rcx, 1")
    asm.WriteText("    cmp     rax, 9")
    asm.WriteText("    ja      .L2")
    asm.WriteText("    lea     rax, [rsp+32]")
    asm.WriteText("    mov     edi, 1")
    asm.WriteText("    sub     rdx, rax")
    asm.WriteText("    xor     eax, eax")
    asm.WriteText("    lea     rsi, [rsp+32+rdx]")
    asm.WriteText("    mov     rdx, r8")
    asm.WriteText("    mov     rax, 1")
    asm.WriteText("    syscall")
    asm.WriteText("    add     rsp, 40")
    asm.WriteText("    ret")
    asm.WriteText("_start:")
	asm.WriteText("    mov rax, ret_stack_end")
	asm.WriteText("    mov [ret_stack_rsp], rax")
    asm.WriteText(";; user program definitions starts here")

	asm.WriteData("section .data")

	asm.WriteBss("section .bss")
	asm.WriteBss("ret_stack_rsp: resq 1")
	asm.WriteBss("ret_stack: resb 65536")
	asm.WriteBss("ret_stack_end:")

	for index, code := range codegen.chunk.code {
		instruction := code.op
		loc := code.loc
		value := code.value

		asm.WriteText("ip_%d:", index)

		switch instruction {
		// Constants
		case OP_PUSH_BOOL:
			boolText := map[int]string{1:"true", 0:"false"} [value.(int)]
			asm.WriteText(";; %s (%s:%d:%d)", boolText, loc.f, loc.l, loc.c)
			asm.WriteText("    mov rax, %d", value)
			asm.WriteText("    push rax")
		case OP_PUSH_INT:
			asm.WriteText(";; %d (%s:%d:%d)", value, loc.f, loc.l, loc.c)
			asm.WriteText("    mov rax, %d", value)
			asm.WriteText("    push rax")
		case OP_PUSH_STR:
			ascii, length := getAsciiValues(value.(string))
			asm.WriteText(";; \"%s\" (%s:%d:%d)", value, loc.f, loc.l, loc.c)
			asm.WriteText("    mov rax, %d", length)
			asm.WriteText("    push rax")
			asm.WriteText("    push str_%d", len(asm.data))
			asm.WriteData("str_%d: db %s", len(asm.data), ascii)

		// Intrinsics
		case OP_ADD:
			asm.WriteText(";; + (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    pop rax")
			asm.WriteText("    pop rbx")
			asm.WriteText("    add rax, rbx")
			asm.WriteText("    push rax")
		case OP_CALL:
			asm.WriteText(";; fs_%d (%s:%d:%d)", value, loc.f, loc.l, loc.c)
			asm.WriteText("    mov rax, rsp")
			asm.WriteText("    mov rsp, [ret_stack_rsp]")
			asm.WriteText("    call fs_%d", value)
			asm.WriteText("    mov [ret_stack_rsp], rsp")
			asm.WriteText("    mov rsp, rax")
		case OP_DIVIDE:
			asm.WriteText(";; / (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    xor rdx, rdx")
			asm.WriteText("    pop rbx")
			asm.WriteText("    pop rax")
			asm.WriteText("    div rbx")
			asm.WriteText("    push rax")
			asm.WriteText("    push rdx")
		case OP_DROP:
			asm.WriteText(";; drop (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    pop rax")
		case OP_DUP:
			asm.WriteText(";; dup (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    pop rax")
			asm.WriteText("    push rax")
			asm.WriteText("    push rax")
		case OP_EQUAL:
			asm.WriteText(";; = (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    xor rcx, rcx")
			asm.WriteText("    mov rdx, 1")
			asm.WriteText("    pop rax")
			asm.WriteText("    pop rbx")
			asm.WriteText("    cmp rax, rbx")
			asm.WriteText("    cmove rcx, rdx")
			asm.WriteText("    push rcx")
		case OP_FUNC_DEFINE:
			asm.WriteText(";; function (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    jmp ip_%d", value)
			asm.WriteText("fs_%d:", code.id)
			asm.WriteText("    sub rsp, 8")
			asm.WriteText("    mov [ret_stack_rsp], rsp")
			asm.WriteText("    mov rsp, rax")
		case OP_GREATER:
			asm.WriteText(";; > (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    xor rcx, rcx")
			asm.WriteText("    mov rdx, 1")
			asm.WriteText("    pop rbx")
			asm.WriteText("    pop rax")
			asm.WriteText("    cmp rax, rbx")
			asm.WriteText("    cmovg rcx, rdx")
			asm.WriteText("    push rcx")
		case OP_GREATER_EQUAL:
			asm.WriteText(";; >= (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    xor rcx, rcx")
			asm.WriteText("    mov rdx, 1")
			asm.WriteText("    pop rbx")
			asm.WriteText("    pop rax")
			asm.WriteText("    cmp rax, rbx")
			asm.WriteText("    cmovge rcx, rdx")
			asm.WriteText("    push rcx")
		case OP_LESS:
			asm.WriteText(";; < (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    xor rcx, rcx")
			asm.WriteText("    mov rdx, 1")
			asm.WriteText("    pop rbx")
			asm.WriteText("    pop rax")
			asm.WriteText("    cmp rax, rbx")
			asm.WriteText("    cmovl rcx, rdx")
			asm.WriteText("    push rcx")
		case OP_LESS_EQUAL:
			asm.WriteText(";; <= (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    xor rcx, rcx")
			asm.WriteText("    mov rdx, 1")
			asm.WriteText("    pop rbx")
			asm.WriteText("    pop rax")
			asm.WriteText("    cmp rax, rbx")
			asm.WriteText("    cmovle rcx, rdx")
			asm.WriteText("    push rcx")
		case OP_MULTIPLY:
			asm.WriteText(";; * (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    pop rax")
			asm.WriteText("    pop rbx")
			asm.WriteText("    mul rbx")
			asm.WriteText("    push rax")
		case OP_NOT_EQUAL:
			asm.WriteText(";; != (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    xor rcx, rcx")
			asm.WriteText("    mov rdx, 1")
			asm.WriteText("    pop rax")
			asm.WriteText("    pop rbx")
			asm.WriteText("    cmp rax, rbx")
			asm.WriteText("    cmovne rcx, rdx")
			asm.WriteText("    push rcx")
		case OP_OVER:
			asm.WriteText(";; over (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    pop rax")
			asm.WriteText("    pop rbx")
			asm.WriteText("    push rbx")
			asm.WriteText("    push rax")
			asm.WriteText("    push rbx")
		case OP_PRINT:
			asm.WriteText(";; print (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    pop rdi")
			asm.WriteText("    call print")
		case OP_SUBSTRACT:
			asm.WriteText(";; - (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    pop rbx")
			asm.WriteText("    pop rax")
			asm.WriteText("    sub rax, rbx")
			asm.WriteText("    push rax")
		case OP_SWAP:
			asm.WriteText(";; swap (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    pop rax")
			asm.WriteText("    pop rbx")
			asm.WriteText("    push rax")
			asm.WriteText("    push rbx")
		case OP_SYSCALL3:
			asm.WriteText(";; SYSCALL3 (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    pop rax")
			asm.WriteText("    pop rdi")
			asm.WriteText("    pop rsi")
			asm.WriteText("    pop rdx")
			asm.WriteText("    syscall")
			asm.WriteText("    push rax")

		// Special
		case OP_END_IF:
			asm.WriteText(";; . [if] (%s:%d:%d)", loc.f, loc.l, loc.c)
		case OP_END_LOOP:
			asm.WriteText(";; . [loop] (%s:%d:%d)", loc.f, loc.l, loc.c)
		case OP_END_FUNC:
			asm.WriteText(";; . [function] (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("fe_%d:", code.id)
			asm.WriteText("    mov rax, rsp")
			asm.WriteText("    mov rsp, [ret_stack_rsp]")
			asm.WriteText("    add rsp, 8")
			asm.WriteText("    ret")
		case OP_IF:
			asm.WriteText(";; if (%s:%d:%d)", loc.f, loc.l, loc.c)
		case OP_JUMP:
			asm.WriteText(";; else (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    jmp ip_%d", value)
		case OP_JUMP_IF_FALSE:
			asm.WriteText(";; do (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    pop rax")
			asm.WriteText("    test rax, rax")
			asm.WriteText("    jz ip_%d", value)
		case OP_LOOP:
			asm.WriteText(";; loop (%s:%d:%d)", loc.f, loc.l, loc.c)
			asm.WriteText("    jmp ip_%d", value)


		case OP_EOC:
			asm.WriteText(";; user program definition ends here")
			asm.WriteText("    mov rax, 60")
			asm.WriteText("    mov rdi, 0")
			asm.WriteText("    syscall")
		}
	}
}

func CodegenRun(chunk Chunk, asm *Assembly) {
	codegen.chunk = chunk
	codegen.asm = asm

	switch runtime.GOOS {
	case "linux":
		generateLinuxX86()
	default:
		Stanczyk.Error("OS currently not supported")
	}
}
