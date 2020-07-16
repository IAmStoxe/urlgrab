package utilities

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// Writes a JSON file to the given path
func WriteToJsonFile(outputPath string, data interface{}) {
	f, err := os.Create(outputPath)
	if nil != err {
		panic(err)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(err)
	}

	_, err = f.WriteString(string(jsonData))
	if err != nil {
		f.Close()
		panic(err)
		return
	}

	err = f.Close()
	if err != nil {
		panic(err)
		return
	}
}

func WriteLines(outputPath string, data []string) {
	f, err := os.Create(outputPath)
	if nil != err {
		panic(err)
	}

	for i := 0; i < len(data); i++ {
		_, err := f.WriteString(fmt.Sprintf("%s\n", data[i]))
		if err != nil {
			f.Close()
			panic(err)
			return
		}
	}

	err = f.Close()
	if err != nil {
		panic(err)
		return
	}
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func ReadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
