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
			case '"':
				ascii += "34,"
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
	entryFunctionName := "start"

	if TheProgram.libcEnabled {
		entryFunctionName = "main"

		out.WriteMetadata("format ELF64")
		out.WriteMetadata("public main")
		out.WriteCode("section '.text' executable")
		out.WriteData("section '.data' writable")
	} else {
		out.WriteMetadata("format ELF64 executable 3")
		out.WriteMetadata("entry start")
		out.WriteCode("segment readable executable")
		out.WriteData("segment readable writable")
	}

    out.WriteCode(";; user program definitions starts here")

	out.WriteData("args_ptr: rq 1")
	out.WriteData("return_stack_rsp: rq 1")
	out.WriteData("return_stack: rb 65536")
	out.WriteData("return_stack_rsp_end:")
	out.WriteData("program_static_mem: rb %d", TheProgram.staticMemorySize)

	for _, function := range TheProgram.chunks {
		currentBindsCount := 0

		if !function.called {
			if !function.internal {
				msg := fmt.Sprintf(MsgTypecheckWarningNotCalled, function.word)
				ReportErrorAtLocation(msg, function.loc)
			}
			continue
		}

		if function.word == "main" {
			mainFuncIP = function.ip
		}

		out.WriteCode("fn%d:", function.ip)
		out.WriteCode(";; start fn %s (%s:%d:%d)", function.word,
			function.loc.f, function.loc.l, function.loc.c)
		out.WriteCode("    sub rsp, %d", function.localMemorySize)
		out.WriteCode("    mov [return_stack_rsp], rsp")
		out.WriteCode("    mov rsp, rax")

		for ipIndex, code := range function.code {
			instruction := code.op
			loc := code.loc
			value := code.value

			out.WriteCode(".ip%d: ;; %s %v (%s:%d:%d)",
				ipIndex, instruction, value, loc.f, loc.l, loc.c)

			switch instruction {

			// CONSTANTS
			case OP_PUSH_BOOL:
				out.WriteCode("    mov rax, %d", value)
				out.WriteCode("    push rax")
			case OP_PUSH_BIND:
				val := value.(int)
				out.WriteCode("    mov rax, [return_stack_rsp]")
				out.WriteCode("    add rax, %d", val * 8)
				out.WriteCode("    push QWORD [rax]")
			case OP_PUSH_BIND_ADDR:
				val := value.(int)
				out.WriteCode("    mov rax, [return_stack_rsp]")
				out.WriteCode("    add rax, %d", val * 8)
				out.WriteCode("    push rax")
			case OP_PUSH_BYTE:
				out.WriteCode("    mov rax, %d", value)
				out.WriteCode("    push rax")
			case OP_PUSH_INT:
				out.WriteCode("    mov rax, %d", value)
				out.WriteCode("    push rax")
			case OP_PUSH_STR:
				ascii := getAsciiValues(value.(string))
				out.WriteCode("    push str_%d", len(out.data))
				out.WriteData("str_%d: db %s", len(out.data), ascii)
			case OP_PUSH_VAR_GLOBAL:
				offset := value.(int)
				out.WriteCode("    mov rax, program_static_mem")
				out.WriteCode("    add rax, %d", offset)
				out.WriteCode("    push QWORD [rax]")
			case OP_PUSH_VAR_GLOBAL_ADDR:
				offset := value.(int)
				out.WriteCode("    mov rax, program_static_mem")
				out.WriteCode("    add rax, %d", offset)
				out.WriteCode("    push rax")
			case OP_PUSH_VAR_LOCAL:
				val := value.(int)
				offset := val + (currentBindsCount * 8)
				out.WriteCode("    mov rax, [return_stack_rsp]")
				out.WriteCode("    add rax, %d", offset)
				out.WriteCode("    push QWORD [rax]")
			case OP_PUSH_VAR_LOCAL_ADDR:
				val := value.(int)
				offset := val + (currentBindsCount * 8)
				out.WriteCode("    mov rax, [return_stack_rsp]")
				out.WriteCode("    add rax, %d", offset)
				out.WriteCode("    push rax")

			case OP_STORE:
				out.WriteCode("    pop rax")
				out.WriteCode("    pop rbx")
				out.WriteCode("    mov [rax], rbx")
			case OP_STORE_BYTE:
				out.WriteCode("    pop rax")
				out.WriteCode("    pop rbx")
				out.WriteCode("    mov [rax], bl")

				// out.WriteCode("    xor rbx, rbx")
				// out.WriteCode("    xor rax, rax")
				// out.WriteCode("    pop rcx")
				// out.WriteCode("    pop rbx")
                // out.WriteCode("    pop rax")
				// out.WriteCode("    add rcx, rax")
                // out.WriteCode("    mov [rcx], bl")
			case OP_LOAD:
				out.WriteCode("    pop rax")
                out.WriteCode("    xor rbx, rbx")
                out.WriteCode("    mov rbx, [rax]")
                out.WriteCode("    push rbx")
			case OP_LOAD_BYTE:
				out.WriteCode("    pop rbx")
				out.WriteCode("    pop rax")
				out.WriteCode("    add rbx, rax")
                out.WriteCode("    xor rcx, rcx")
                out.WriteCode("    mov cl, [rbx]")
                out.WriteCode("    push rcx")

			// NUMBER ARITHMETICS
			case OP_ADD:
				out.WriteCode("    pop rax")
				out.WriteCode("    pop rbx")
				out.WriteCode("    add rax, rbx")
				out.WriteCode("    push rax")
			case OP_DIVIDE:
				out.WriteCode("    xor rdx, rdx")
				out.WriteCode("    pop rbx")
				out.WriteCode("    pop rax")
				out.WriteCode("    div rbx")
				out.WriteCode("    push rax")
			case OP_MODULO:
				out.WriteCode("    xor rdx, rdx")
				out.WriteCode("    pop rbx")
				out.WriteCode("    pop rax")
				out.WriteCode("    div rbx")
				out.WriteCode("    push rdx")
			case OP_MULTIPLY:
				out.WriteCode("    pop rax")
				out.WriteCode("    pop rbx")
				out.WriteCode("    mul rbx")
				out.WriteCode("    push rax")
			case OP_SUBSTRACT:
				out.WriteCode("    pop rbx")
				out.WriteCode("    pop rax")
				out.WriteCode("    sub rax, rbx")
				out.WriteCode("    push rax")

			// BOOLEAN ARITHMETICS
			case OP_EQUAL:
				out.WriteCode("    xor rcx, rcx")
				out.WriteCode("    mov rdx, 1")
				out.WriteCode("    pop rax")
				out.WriteCode("    pop rbx")
				out.WriteCode("    cmp rax, rbx")
				out.WriteCode("    cmove rcx, rdx")
				out.WriteCode("    push rcx")
			case OP_GREATER:
				out.WriteCode("    xor rcx, rcx")
				out.WriteCode("    mov rdx, 1")
				out.WriteCode("    pop rbx")
				out.WriteCode("    pop rax")
				out.WriteCode("    cmp rax, rbx")
				out.WriteCode("    cmovg rcx, rdx")
				out.WriteCode("    push rcx")
			case OP_GREATER_EQUAL:
				out.WriteCode("    xor rcx, rcx")
				out.WriteCode("    mov rdx, 1")
				out.WriteCode("    pop rbx")
				out.WriteCode("    pop rax")
				out.WriteCode("    cmp rax, rbx")
				out.WriteCode("    cmovge rcx, rdx")
				out.WriteCode("    push rcx")
			case OP_LESS:
				out.WriteCode("    xor rcx, rcx")
				out.WriteCode("    mov rdx, 1")
				out.WriteCode("    pop rbx")
				out.WriteCode("    pop rax")
				out.WriteCode("    cmp rax, rbx")
				out.WriteCode("    cmovl rcx, rdx")
				out.WriteCode("    push rcx")
			case OP_LESS_EQUAL:
				out.WriteCode("    xor rcx, rcx")
				out.WriteCode("    mov rdx, 1")
				out.WriteCode("    pop rbx")
				out.WriteCode("    pop rax")
				out.WriteCode("    cmp rax, rbx")
				out.WriteCode("    cmovle rcx, rdx")
				out.WriteCode("    push rcx")

			// FLOW CONTROL
			case OP_IF_START:
				val := value.(int)
				out.WriteCode("    pop rax")
				out.WriteCode("    test rax, rax")
				out.WriteCode("    jz .ifelse%d", val)
			case OP_IF_ELSE:
				val := value.(int)
				out.WriteCode("    jmp .ifthen%d", val)
				out.WriteCode(".ifelse%d:", val)
			case OP_IF_END:
				val := value.(int)
				out.WriteCode(".ifthen%d:", val)
			case OP_LOOP_END:
				val := value.(int)
				out.WriteCode("    jmp .ltest%d", val)
				out.WriteCode(".lend%d:", val)
			case OP_LOOP_SETUP:
				val := value.(int)
				out.WriteCode(".ltest%d:", val)
			case OP_LOOP_START:
				val := value.(int)
				out.WriteCode("    pop rax")
				out.WriteCode("    test rax, rax")
				out.WriteCode("    jz .lend%d", val)

			// INTRINSICS
			case OP_ARGC:
				out.WriteCode("    mov rax, [args_ptr]")
                out.WriteCode("    mov rax, [rax]")
                out.WriteCode("    push rax")
			case OP_ARGV:
				out.WriteCode("    mov rax, [args_ptr]")
				out.WriteCode("    add rax, 8")
                out.WriteCode("    push rax")
			case OP_ASSEMBLY:
				val := value.(ASMValue)
				for _, s := range val.body {
					out.WriteCode("    %s", s)
				}
			case OP_FUNCTION_CALL:
				ip := value.(int)
				out.WriteCode("    mov rax, rsp")
				out.WriteCode("    mov rsp, [return_stack_rsp]")
				out.WriteCode("    call fn%d", ip)
				out.WriteCode("    mov [return_stack_rsp], rsp")
				out.WriteCode("    mov rsp, rax")
			case OP_REBIND:
				index := value.(int)
				out.WriteCode("    mov rax, [return_stack_rsp]")
				out.WriteCode("    pop rbx")
				out.WriteCode("    mov [rax+%d], rbx", index * 8)
			case OP_LET_BIND:
				newBinds := value.(int)
				out.WriteCode("    mov rax, [return_stack_rsp]")
				out.WriteCode("    sub rax, %d", newBinds * 8)
				out.WriteCode("    mov [return_stack_rsp], rax")
				for i := newBinds; i > 0; i-- {
					out.WriteCode("    pop rbx")
					out.WriteCode("    mov [rax+%d], rbx", (i - 1) * 8)
				}
				currentBindsCount += newBinds
			case OP_LET_UNBIND:
				unbindCount := value.(int)
				out.WriteCode("    mov rax, [return_stack_rsp]")
				out.WriteCode("    add rax, %d", unbindCount * 8)
				out.WriteCode("    mov [return_stack_rsp], rax")
				currentBindsCount -= unbindCount
			case OP_NOT_EQUAL:
				out.WriteCode("    xor rcx, rcx")
				out.WriteCode("    mov rdx, 1")
				out.WriteCode("    pop rax")
				out.WriteCode("    pop rbx")
				out.WriteCode("    cmp rax, rbx")
				out.WriteCode("    cmovne rcx, rdx")
				out.WriteCode("    push rcx")
			case OP_RET:
				if currentBindsCount > 0 {
					out.WriteCode("    mov rax, [return_stack_rsp]")
					out.WriteCode("    add rax, %d", currentBindsCount * 8)
					out.WriteCode("    mov [return_stack_rsp], rax")
				}
				out.WriteCode("    mov rax, rsp")
				out.WriteCode("    mov rsp, [return_stack_rsp]")
				out.WriteCode("    add rsp, %d", function.localMemorySize)
				out.WriteCode("    ret")

			// Special
			case OP_CAST:
			}
		}

		out.WriteCode(";; end fn %s (%s:%d:%d)", function.word,
			function.loc.f, function.loc.l, function.loc.c)
	}

	out.WriteCode(";; user program definition ends here")
	out.WriteCode("%s:", entryFunctionName)
	out.WriteCode("    mov [args_ptr], rsp")
	out.WriteCode("    mov rax, return_stack_rsp_end")
	out.WriteCode("    mov [return_stack_rsp], rax")
	out.WriteCode("    call fn%d", mainFuncIP)
	out.WriteCode("    mov rax, 60")
	out.WriteCode("    mov rdi, 0")
	out.WriteCode("    syscall")
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
