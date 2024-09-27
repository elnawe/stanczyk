Stanczyk is a work in progress project, and so it has a list of things I would like to complete before leaving it, again (or maybe not)

X Support `extern` keyword for ASM function and interop
- Make function registration its own pass for the compiler, compile the content on a different pass.
- Change the OP_WORD to instead be OP_FUNCTION_CALL when it's a registered function
- Add extra checks for extern, specially when returning values
- Support `var` creation
- Add an interpreter to simulate code execution (this will give it temporary Windows support)
