package skc

import (
	"fmt"
	"runtime"
)

type Codegen struct {
	out *OutputCode
}

var codegen Codegen

func getAsciiValues(s string) string {
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
			case 'n':
				ascii += "10,"
			case 'e':
				ascii += "27,"
			}

			nextEscaped = false
			continue
		}

		val := fmt.Sprintf("%d,", c)
		ascii += val
	}

	ascii += "0"

	return ascii
}

func generateLinuxX64() {
	mainFuncIP := -1
	out := codegen.out

	out.WriteText("section .text")
    out.WriteText("global _start")
    out.WriteText(";; user program definitions starts here")

	out.WriteData("section .data")

	out.WriteBss("section .bss")
	out.WriteBss("args: resq 1")
	out.WriteBss("return_stack_rsp: resq 1024")
	out.WriteBss("return_stack: resb 65536")
	out.WriteBss("return_stack_rsp_end:")

	for _, function := range TheProgram.chunks {
		currentBindsCount := 0

		if !function.called {
			if !function.internal {
				msg := fmt.Sprintf(MsgTypecheckWarningNotCalled, function.name)
				ReportErrorAtLocation(msg, function.loc)
			}
			continue
		}

		if function.name == "main" {
			mainFuncIP = function.ip
		}

		out.WriteText("fn%d:", function.ip)
		out.WriteText(";; start fn %s (%s:%d:%d)", function.name,
			function.loc.f, function.loc.l, function.loc.c)
		out.WriteText("    sub rsp, 0")
		out.WriteText("    mov [return_stack_rsp], rsp")
		out.WriteText("    mov rsp, rax")

		for ipIndex, code := range function.code {
			instruction := code.op
			loc := code.loc
			value := code.value

			out.WriteText(".ip%d:", ipIndex)

			switch instruction {

			// CONSTANTS
			case OP_PUSH_BOOL:
				boolText := map[int]string{1:"true", 0:"false"} [value.(int)]
				out.WriteText(";; %s (%s:%d:%d)", boolText, loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, %d", value)
				out.WriteText("    push rax")
			case OP_PUSH_BIND:
				val := value.(int)
				out.WriteText(";; bind \"%d\" (%s:%d:%d)", val, loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, [return_stack_rsp]")
				out.WriteText("    add rax, %d", val * 8)
				out.WriteText("    push QWORD [rax]")
			case OP_PUSH_CHAR:
				out.WriteText(";; '%d' (%s:%d:%d)", value, loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, %d", value)
				out.WriteText("    push rax")
			case OP_PUSH_INT:
				out.WriteText(";; %d (%s:%d:%d)", value, loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, %d", value)
				out.WriteText("    push rax")
			case OP_PUSH_PTR:
				mem := value.(Object)
				out.WriteText(";; %s (%s:%d:%d)", mem.word, loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, mem_%d", mem.id)
				out.WriteText("    push rax")
			case OP_PUSH_STR:
				ascii := getAsciiValues(value.(string))
				out.WriteText(";; \"%s\" (%s:%d:%d)", value, loc.f, loc.l, loc.c)
				out.WriteText("    push str_%d", len(out.data))
				out.WriteData("str_%d: db %s", len(out.data), ascii)

			// NUMBER ARITHMETICS
			case OP_ADD:
				out.WriteText(";; + (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    pop rax")
				out.WriteText("    pop rbx")
				out.WriteText("    add rax, rbx")
				out.WriteText("    push rax")
			case OP_DIVIDE:
				out.WriteText(";; / (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    xor rdx, rdx")
				out.WriteText("    pop rbx")
				out.WriteText("    pop rax")
				out.WriteText("    div rbx")
				out.WriteText("    push rax")
			case OP_MODULO:
				out.WriteText(";; % (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    xor rdx, rdx")
				out.WriteText("    pop rbx")
				out.WriteText("    pop rax")
				out.WriteText("    div rbx")
				out.WriteText("    push rdx")
			case OP_MULTIPLY:
				out.WriteText(";; * (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    pop rax")
				out.WriteText("    pop rbx")
				out.WriteText("    mul rbx")
				out.WriteText("    push rax")
			case OP_SUBSTRACT:
				out.WriteText(";; - (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    pop rbx")
				out.WriteText("    pop rax")
				out.WriteText("    sub rax, rbx")
				out.WriteText("    push rax")

			// BOOLEAN ARITHMETICS
			case OP_EQUAL:
				out.WriteText(";; = (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    xor rcx, rcx")
				out.WriteText("    mov rdx, 1")
				out.WriteText("    pop rax")
				out.WriteText("    pop rbx")
				out.WriteText("    cmp rax, rbx")
				out.WriteText("    cmove rcx, rdx")
				out.WriteText("    push rcx")
			case OP_GREATER:
				out.WriteText(";; > (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    xor rcx, rcx")
				out.WriteText("    mov rdx, 1")
				out.WriteText("    pop rbx")
				out.WriteText("    pop rax")
				out.WriteText("    cmp rax, rbx")
				out.WriteText("    cmovg rcx, rdx")
				out.WriteText("    push rcx")
			case OP_GREATER_EQUAL:
				out.WriteText(";; >= (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    xor rcx, rcx")
				out.WriteText("    mov rdx, 1")
				out.WriteText("    pop rbx")
				out.WriteText("    pop rax")
				out.WriteText("    cmp rax, rbx")
				out.WriteText("    cmovge rcx, rdx")
				out.WriteText("    push rcx")
			case OP_LESS:
				out.WriteText(";; < (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    xor rcx, rcx")
				out.WriteText("    mov rdx, 1")
				out.WriteText("    pop rbx")
				out.WriteText("    pop rax")
				out.WriteText("    cmp rax, rbx")
				out.WriteText("    cmovl rcx, rdx")
				out.WriteText("    push rcx")
			case OP_LESS_EQUAL:
				out.WriteText(";; <= (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    xor rcx, rcx")
				out.WriteText("    mov rdx, 1")
				out.WriteText("    pop rbx")
				out.WriteText("    pop rax")
				out.WriteText("    cmp rax, rbx")
				out.WriteText("    cmovle rcx, rdx")
				out.WriteText("    push rcx")

			// FLOW CONTROL
			case OP_LOOP_END:
				val := value.(int)
				out.WriteText(";; OP_LOOP_END %d (%s:%d:%d)", val, loc.f, loc.l, loc.c)
				out.WriteText("    jmp .ltest%d", val)
				out.WriteText(".lend%d:", val)
			case OP_LOOP_SETUP:
				val := value.(int)
				out.WriteText(";; OP_LOOP_SETUP %d (%s:%d:%d)", val, loc.f, loc.l, loc.c)
				out.WriteText(".ltest%d:", val)
			case OP_LOOP_START:
				val := value.(int)
				out.WriteText(";; OP_LOOP_START %d (%s:%d:%d)", val, loc.f, loc.l, loc.c)
				out.WriteText("    pop rax")
				out.WriteText("    test rax, rax")
				out.WriteText("    jz .lend%d", val)

			// INTRINSICS
			case OP_ARGC:
				out.WriteText(";; argc (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, [args]")
                out.WriteText("    mov rax, [rax]")
                out.WriteText("    push rax")
			case OP_ARGV:
				out.WriteText(";; argv (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, [args]")
				out.WriteText("    add rax, 8")
                out.WriteText("    push rax")
			case OP_ASSEMBLY:
				val := value.(Assembly)
				out.WriteText(";; asm ( (%s:%d:%d)", loc.f, loc.l, loc.c)
				for _, s := range val.body {
					out.WriteText("    %s", s)
				}
				out.WriteText(";; ) asm (%s:%d:%d)", loc.f, loc.l, loc.c)
			case OP_FUNCTION_CALL:
				fnCall := value.(FunctionCall)
				out.WriteText(";; call fn %s (%s:%d:%d)", fnCall.name, loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, rsp")
				out.WriteText("    mov rsp, [return_stack_rsp]")
				out.WriteText("    call fn%d", fnCall.ip)
				out.WriteText("    mov [return_stack_rsp], rsp")
				out.WriteText("    mov rsp, rax")
			case OP_REBIND:
				index := value.(int)
				out.WriteText(";; OP_REBIND %d (%s:%d:%d)", index, loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, [return_stack_rsp]")
				out.WriteText("    pop rbx")
				out.WriteText("    mov [rax+%d], rbx", index * 8)
			case OP_LET_BIND:
				newBinds := value.(int)
				out.WriteText(";; let [%d] in (%s:%d:%d)", newBinds, loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, [return_stack_rsp]")
				out.WriteText("    sub rax, %d", newBinds * 8)
				out.WriteText("    mov [return_stack_rsp], rax")
				for i := newBinds; i > 0; i-- {
					out.WriteText("    pop rbx")
					out.WriteText("    mov [rax+%d], rbx", (i - 1) * 8)
				}
				currentBindsCount += newBinds
			case OP_LET_UNBIND:
				unbindCount := value.(int)
				out.WriteText(";; unbinding: %d (%s:%d:%d)", unbindCount, loc.f, loc.l, loc.c)
				out.WriteText("    mov rax, [return_stack_rsp]")
				out.WriteText("    add rax, %d", unbindCount * 8)
				out.WriteText("    mov [return_stack_rsp], rax")
				currentBindsCount -= unbindCount
			case OP_CAST:
				out.WriteText(";; cast to %s (%s:%d:%d)",
					getDataTypeName(value.(DataType)), loc.f, loc.l, loc.c)
			case OP_LOAD8:
				out.WriteText(";; ->8 (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    pop rax")
                out.WriteText("    xor rbx, rbx")
                out.WriteText("    mov bl, [rax]")
                out.WriteText("    push rbx")
			case OP_LOAD16:
				out.WriteText(";; ->16 (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    pop rax")
                out.WriteText("    xor rbx, rbx")
                out.WriteText("    mov bx, [rax]")
                out.WriteText("    push rbx")
			case OP_LOAD32:
				out.WriteText(";; ->32 (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    pop rax")
                out.WriteText("    xor rbx, rbx")
                out.WriteText("    mov ebx, [rax]")
                out.WriteText("    push rbx")
			case OP_LOAD64:
				out.WriteText(";; ->64 (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    pop rax")
                out.WriteText("    xor rbx, rbx")
                out.WriteText("    mov rbx, [rax]")
                out.WriteText("    push rbx")
			case OP_NOT_EQUAL:
				out.WriteText(";; != (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    xor rcx, rcx")
				out.WriteText("    mov rdx, 1")
				out.WriteText("    pop rax")
				out.WriteText("    pop rbx")
				out.WriteText("    cmp rax, rbx")
				out.WriteText("    cmovne rcx, rdx")
				out.WriteText("    push rcx")
			case OP_RET:
				out.WriteText(";; ret (%s:%d:%d)", loc.f, loc.l, loc.c)

				if currentBindsCount > 0 {
					out.WriteText("    mov rax, [return_stack_rsp]")
					out.WriteText("    add rax, %d", currentBindsCount * 8)
					out.WriteText("    mov [return_stack_rsp], rax")
				}

				out.WriteText("    mov rax, rsp")
				out.WriteText("    mov rsp, [return_stack_rsp]")
				out.WriteText("    add rsp, %d", value)
				out.WriteText("    ret")
			case OP_STORE8:
				out.WriteText(";; <-8 (%s:%d:%d)", loc.f, loc.l, loc.c)
                out.WriteText("    pop rbx")
                out.WriteText("    pop rax")
                out.WriteText("    mov [rax], bl")
			case OP_STORE16:
				out.WriteText(";; <-16 (%s:%d:%d)", loc.f, loc.l, loc.c)
                out.WriteText("    pop rbx")
                out.WriteText("    pop rax")
                out.WriteText("    mov [rax], bx")
			case OP_STORE32:
				out.WriteText(";; <-32 (%s:%d:%d)", loc.f, loc.l, loc.c)
                out.WriteText("    pop rbx")
                out.WriteText("    pop rax")
                out.WriteText("    mov [rax], ebx")
			case OP_STORE64:
				out.WriteText(";; <-64 (%s:%d:%d)", loc.f, loc.l, loc.c)
                out.WriteText("    pop rbx")
                out.WriteText("    pop rax")
                out.WriteText("    mov [rax], rbx")
			case OP_TAKE:
				out.WriteText(";; take (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    pop rax")
				out.WriteText("    push rax")

			// Special
			case OP_END_IF:
				out.WriteText(";; ) [if] (%s:%d:%d)", loc.f, loc.l, loc.c)
			case OP_END_LOOP:
				out.WriteText(";; ) [loop] (%s:%d:%d)", loc.f, loc.l, loc.c)
			case OP_JUMP:
				out.WriteText(";; ) else ( (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    jmp .ip%d", value)
			case OP_JUMP_IF_FALSE:
				out.WriteText(";; then ( (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    pop rax")
				out.WriteText("    test rax, rax")
				out.WriteText("    jz .ip%d", value)
			case OP_LOOP:
				out.WriteText(";; loop ( (%s:%d:%d)", loc.f, loc.l, loc.c)
				out.WriteText("    jmp .ip%d", value)
			}
		}

		out.WriteText(";; end fn %s (%s:%d:%d)", function.name,
			function.loc.f, function.loc.l, function.loc.c)
	}

	out.WriteText(";; user program definition ends here")
	out.WriteText("_start:")
	out.WriteText("    mov [args], rsp")
	out.WriteText("    mov rax, return_stack_rsp_end")
	out.WriteText("    mov [return_stack_rsp], rax")
	out.WriteText("    call fn%d", mainFuncIP)
	out.WriteText("    mov rax, 60")
	out.WriteText("    mov rdi, 0")
	out.WriteText("    syscall")

	for _, v := range TheProgram.variables {
		out.WriteBss("mem_%d: resb %d", v.id, v.value)
	}
}

func CodegenRun(out *OutputCode) {
	codegen.out = out

	switch runtime.GOOS {
	case "linux":
		generateLinuxX64()
	default:
		Stanczyk.Error("OS currently not supported")
	}
}
