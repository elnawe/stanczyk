# The Stańczyk Programming Language

[![CI](https://img.shields.io/github/actions/workflow/status/elnawe/stanczyk/ci.yml?style=for-the-badge)](https://github.com/elnawe/stanczyk/actions/workflows/ci.yml)
[![Commits](https://img.shields.io/github/commit-activity/w/elnawe/stanczyk?style=for-the-badge)](https://github.com/elnawe/stanczyk/commits/main)
[![License](https://img.shields.io/github/license/elnawe/stanczyk?style=for-the-badge)](https://github.com/elnawe/stanczyk/blob/main/LICENSE)

![Jan Matejko's Stańczyk](https://upload.wikimedia.org/wikipedia/commons/thumb/7/78/Jan_Matejko%2C_Sta%C5%84czyk.jpg/2560px-Jan_Matejko%2C_Sta%C5%84czyk.jpg)

**NOTE: This is a work in progress, things can change without any notice. Use with discretion.**

This repository contains the source code for [Stańczyk]. You can find the compiler, standard library and documentation.

[Stańczyk]: https://stanczyk-lang.org

## What is Stańczyk?

Stańczyk is a [concatenative](https://en.wikipedia.org/wiki/Concatenative_programming_language) Programming Language that compiles to Assembly and then to an executable using the GCC back-end. It writes in Reverse Polish Notation and fits into the [stack-oriented programming paradigm](https://en.wikipedia.org/wiki/Stack-oriented_programming).

## Installation

- TODO: Add installation

### Dependencies

Make sure you have the following dependencies in your system before building Stańczyk:

* `git`
* `gcc` (build the source and also used to build the Assembly output)

## My first program

A simple *Hello, Stańczyk* program could be:

```
using "io"

"Hello, Stańczyk\n" write
```

You can find more examples on [demos](demo)

## Unit tests

After you get the Stańczyk Compiler executable, you can run `./test.sh`.

## TODO

[ ] (compile.go) Add support to multi constant/variable definition with const/var (...) tuples
[ ] (scanner.go) (ir.go) Rename all _CHAR references to _BYTE (including types)
