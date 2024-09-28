package skc

import (
	"fmt"
	"time"
)

type CompilationStep int

const (
	stepFrontend CompilationStep = iota
	stepValidate
	stepCodegen
	stepOutput
	stepBackend
)

var (
	started bool
	lastStep CompilationStep
	startTime time.Time
)

var outputMsg string
var TheProgram Program

func getStepName(step CompilationStep) string {
	switch step {
	case stepFrontend:	return "Front-end compilation"
	case stepValidate:  return "Validation"
	case stepCodegen:	return "Code generation"
	case stepOutput:	return "Output to ASM"
	case stepBackend:	return "Back-end compilation"
	default:			return "Unreachable"
	}
}

func timedFunction(step CompilationStep) {
	if started {
		elapsed := time.Since(startTime)
		ms := elapsed.Milliseconds()

		if ms >= 1000 {
			msg := fmt.Sprintf("→ done in %.02fs\n", elapsed.Seconds())
			outputMsg += msg
		} else {
			msg := fmt.Sprintf("→ done in %dms\n", ms)
			outputMsg += msg
		}
		started = false

		if step != lastStep {
			timedFunction(step)
		}
	} else {
		msg := fmt.Sprintf("%s %-25s", MsgCliPrefix, getStepName(step))
		outputMsg += msg
		lastStep = step
		startTime = time.Now()
		started = true
	}
}

func RunTasks() {
	var (
		asm   Assembly
	)

	timedFunction(stepFrontend)
	FrontendRun()

	timedFunction(stepValidate)
	ValidateRun()

	timedFunction(stepCodegen)
	CodegenRun(&asm)

	timedFunction(stepOutput)
	OutputRun(asm)

	timedFunction(stepBackend)
	BackendRun()

	timedFunction(lastStep)

	Stanczyk.Message(outputMsg)
}
