PROJECT_NAME  := Stanczyk
OUT_DIR       := ./bin
LIBS_DIR      := ./libs
OUTPUT        := $(OUT_DIR)/skc

all: clean $(OUT_DIR) $(LIBS_DIR) compile

clean:
	rm -rf $(OUT_DIR)

$(OUT_DIR):
	mkdir -p $@

compile:
	cp -r $(LIBS_DIR) $(OUT_DIR)
	go build -o $(OUTPUT)
