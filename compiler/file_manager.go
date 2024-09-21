package skc

import (
	"bufio"
	"os"
	"strings"
)

type File struct {
	filename string
	source   string
	internal bool
}

type FileManager struct {
	files []File
}

func getParsedSourceFile(path string) string {
	f, err := os.Open(path)
	CheckError(err, "file_manager.go-1")
	defer f.Close()

	var result strings.Builder

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		addingNumber := false

		for index := 0; index < len(line); index++ {
			c := line[index]

			if IsDigit(c) {
				result.WriteByte(c)
				for Advance(&c, line, &index) && c != ' ' {
					if c != '_' {
						result.WriteByte(c)
					}
				}

				result.WriteByte(' ')
				continue
			}

			if addingNumber {
				if c == '_' {
					continue
				}

				if c == ' ' {
					addingNumber = false
				}

				result.WriteByte(c)
			}

			if c == ';' {
				break
			}

			if IsDigit(c) {
				addingNumber = true
			}

			result.WriteByte(c)
		}

		result.WriteByte('\n')
	}

	return result.String()
}

func (this *FileManager) Open(filename string) {
	path := ""
	internal := false

	if (strings.Contains(filename, ".sk")) {
		path = Stanczyk.workspace.pDir + "/" + filename
	} else {
		path = Stanczyk.workspace.cDir + "/libs/" + filename + ".sk"
		internal = true
	}

	for _, f := range this.files {
		if f.filename == path {
			// File already opened so we don't need to do it again
			return
		}
	}

	_, err := os.Stat(path)
	CheckError(err, "file_manager.go-2")

	this.files = append(this.files, File{
		filename: path,
		source: getParsedSourceFile(path),
		internal: internal,
	})
}
