package mod

import (
	"errors"
	"fi/def"
	"github.com/AkvicorEdwards/arg"
	"github.com/AkvicorEdwards/encrypt"
	"github.com/AkvicorEdwards/util"
)

/*
enc encrypt file
	size = 1 [filename]
	-p password
	-i iv
	-o out file
 */

func AddEnc(order int) (err error) {
	err = arg.AddCommand([]string{"enc"}, order, 1, "Encrypt file",
		"Encrypt file", "", "[filename]", Enc, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"enc", "-p"}, 10, 1, 10, "Specify password",
	"Specify password", "", "[password]", EncArgP, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"enc", "-i"}, 10, 1, 10, "Specify IV",
		"Specify IV", "", "[iv]", EncArgI, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"enc", "-o"}, 10, 1, 10,
		"Extract the file to this file", "Specify output filename",
		"", "[filename]", EncArgO, nil)
	if err != nil {
		return err
	}
	return nil
}

var ErrEncNotExist = errors.New("target not exist")

var encVarPassword = ""
var encVarIV = ""
var encVarTargetFile = ""

func Enc(str []string) (err error) {
	originalFilename := str[1]
	targetFilename := encVarTargetFile
	if len(targetFilename) == 0 {
		targetFilename = originalFilename+".enc"
	}
	password := def.CalculatePassword([]byte(encVarPassword))
	iv := []byte(encVarIV)
	if len(iv) == 0 {
		iv = password[:16]
	}
	if util.FileStat(originalFilename) != 2 {
		return ErrEncNotExist
	}

	err = encrypt.AesCTREncryptFile(originalFilename, targetFilename, password, iv)

	return err
}

func EncArgP(args []string) error {
	encVarPassword = args[1]
	return nil
}

func EncArgI(args []string) error {
	encVarIV = args[1]
	return nil
}

func EncArgO(args []string) error {
	encVarTargetFile = args[1]
	return nil
}