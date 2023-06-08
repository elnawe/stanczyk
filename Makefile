PROJECT_NAME  := Stanczyk
CC            := gcc
CFLAGS        := -Wall -std=c99 -Wpedantic
RELEASE_FLAGS := -O3
DEBUG_FLAGS   := -g -ggdb -O0
NAME          := skc
SRC           := $(wildcard src/*.c)

default: main

main:
	@ $(CC) $(CFLAGS) $(DEBUG_FLAGS) $(SRC) -o $(NAME)

debug:
	@ $(CC) $(CFLAGS) $(DEBUG_FLAGS) $(SRC) -o $(NAME) -DDEBUG_MODE

release:
	@ $(CC) $(CFLAGS) $(RELEASE_FLAGS) $(SRC) -o $(NAME)

go:
	@ go build -o ./skc ./code
