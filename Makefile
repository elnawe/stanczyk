PROJECT_NAME  := Stanczyk
NAME          := ./skc
CODE          := ./compiler

default: main

main:
	@ odin build $(CODE) -out:$(NAME)
