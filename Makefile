PROJECT_NAME  := Stanczyk
NAME          := ./skc
CODE          := ./code

default: main

main:
	@ go build $(CODE) -o $(NAME)
