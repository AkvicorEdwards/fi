package mod

import (
	"errors"
	"fi/def"
	"github.com/AkvicorEdwards/arg"
	"github.com/AkvicorEdwards/encrypt"
	"github.com/AkvicorEdwards/util"
)

/*
dec decrypt file
	size = 1 [filename]
	-p password
	-i iv
	-o out file
 */


func AddDec(order int) (err error) {
	err = arg.AddCommand([]string{"dec"}, order, 1, "Decrypt file",
		"Decrypt file", "", "[filename]", Dec, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"dec", "-p"}, 10, 1, 10, "Specify password",
		"Specify password", "", "[password]", DecArgP, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"dec", "-i"}, 10, 1, 10, "Specify IV",
		"Specify IV", "", "[iv]", DecArgI, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"dec", "-o"}, 10, 1, 10,
		"Extract the file to this file", "Specify output filename",
		"", "[filename]", DecArgO, nil)
	if err != nil {
		return err
	}
	return nil
}

var ErrDecNotExist = errors.New("target not exist")

var decVarPassword = ""
var decVarIV = ""
var decVarTargetFile = ""

func Dec(str []string) (err error) {
	originalFilename := str[1]
	targetFilename := decVarTargetFile
	if len(targetFilename) == 0 {
		targetFilename = originalFilename+".dec"
	}
	password := def.CalculatePassword([]byte(decVarPassword))
	iv := []byte(decVarIV)
	if len(iv) == 0 {
		iv = password[:16]
	}
	if util.FileStat(originalFilename) != 2 {
		return ErrDecNotExist
	}

	err = encrypt.AesCTRDecryptFile(originalFilename, targetFilename, password, iv)

	return err
}

func DecArgP(args []string) error {
	decVarPassword = args[1]
	return nil
}

func DecArgI(args []string) error {
	decVarIV = args[1]
	return nil
}

func DecArgO(args []string) error {
	decVarTargetFile = args[1]
	return nil
}




