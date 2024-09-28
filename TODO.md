Stanczyk is a work in progress project, and so it has a list of things I would like to complete before leaving it, again (or maybe not)

X Support `extern` keyword for ASM function and interop
X Make function registration its own pass for the compiler, compile the content on a different pass.
X Change the OP_WORD to instead be OP_FUNCTION_CALL when it's a registered function
X Allow variables in extern (expandWord should change so it can return other types)
- Add extra checks for extern, specially when returning values
- Support `var` creation
- Add an interpreter to simulate code execution (this will give it temporary Windows support)
- Testing library to work with `skc test file.sk` that runs main-test function and allows the user to check for code output as well.
