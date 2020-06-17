package cmd

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/spf13/pflag"
)

type enumArg struct {
	v       *uint32
	vName   string
	choices map[string]uint32
}

func (v *enumArg) String() string {
	return v.vName
}

func (v *enumArg) Set(s string) error {
	x, ok := v.choices[s]
	if !ok {
		return errors.New("bad enum value")
	}
	*v.v = x
	v.vName = s
	return nil
}

func (_ *enumArg) Type() string {
	return "enumeration"
}

func flagEnumVar(fs *pflag.FlagSet, dest *uint32, name string, value string, usage string, choices map[string]uint32) {
	var choiceNames []string
	for x, _ := range choices {
		choiceNames = append(choiceNames, x)
	}
	usage = fmt.Sprintf("%s %v", usage, choiceNames)
	fs.Var(&enumArg{dest, value, choices}, name, usage)
	*dest = choices[value]
}

func readMaybePEM(name, blockType string) []byte {
	result, err := ioutil.ReadFile(name)
	if err != nil {
		log.Println("Error reading key file", err)
		os.Exit(1)
	}

	// Try PEM
	if block, rest := pem.Decode(result); block != nil {
		// Good pem
		if len(rest) != 0 {
			log.Println("Got extra data in key file")
			os.Exit(1)
		}
		if block.Type != blockType {
			log.Printf("Expected %s, got %#v\n", blockType,
				block.Type)
			os.Exit(1)
		}
		result = block.Bytes
	}

	return result
}
