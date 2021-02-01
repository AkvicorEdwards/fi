package mod

import (
	"errors"
	"fmt"
	"github.com/AkvicorEdwards/arg"
	"github.com/AkvicorEdwards/press"
	"github.com/AkvicorEdwards/util"
)

/*
tgz tar gz file
	size = 1 [filename]
	-o out file
	-t tar
	-g gz
	-tg tgz (default)
 */

func AddTgz(order int) (err error) {
	err = arg.AddCommand([]string{"tgz"}, order, -1, "Compress file",
		"Compress file", "", "[target]", Tgz, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"tgz", "-o"}, 10, 1, 10,
	"Extract the file to this file", "Specify output filename",
	"", "[filename]", TgzArgO, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"tgz", "-t"}, 20, 0, 10, "Tar target file",
		"Tar target file", "", "", TgzArgT, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"tgz", "-g"}, 30, 0, 10, "Gzip target file",
		"Gzip target file", "", "", TgzArgG, nil)
	err = AddOptionDisplayLog([]string{"tgz"}, 60, 200)
	if err != nil {
		return err
	}
	return nil
}

var ErrTgzNotExist = errors.New("target not exist")

var tgzVarTar = false
var tgzVarGzip = false
var tgzVarTargetFile = ""

func Tgz(str []string) (err error) {
	if len(str) < 2 {
		Println("No target file specified")
		return ErrTgzNotExist
	}
	originalFilename := str[1:]
	targetFilename := tgzVarTargetFile
	if !tgzVarTar && !tgzVarGzip {
		tgzVarTar = true
		tgzVarGzip = true
	}
	if len(originalFilename) > 1 {
		Println("The number of files is greater than 1")
		tgzVarTar = true
	}

	for _, v := range originalFilename {
		if stat := util.FileStat(v); stat == 0 {
			fmt.Printf("[%s] not exist\n", v)
			return ErrTgzNotExist
		} else if stat == 1 {
			tgzVarTar = true
		}
	}

	if tgzVarTar && tgzVarGzip {
		if len(targetFilename) == 0 {
			targetFilename = originalFilename[0] + ".tgz"
		}
		err = press.Tgz(originalFilename, "", targetFilename)
	} else if tgzVarTar {
		if len(targetFilename) == 0 {
			targetFilename = originalFilename[0] + ".tar"
		}
		err = press.Tar(originalFilename, "", targetFilename)
	} else if tgzVarGzip {
		if len(targetFilename) == 0 {
			targetFilename = originalFilename[0] + ".gz"
		}
		err = press.Gzip(originalFilename[0], "", targetFilename)
	}

	if err != nil {
		Println(err)
		return err
	}
	fmt.Println("Finished")
	return nil
}

func TgzArgO(args []string) error {
	tgzVarTargetFile = args[1]
	return nil
}

func TgzArgT([]string) error {
	tgzVarTar = true
	return nil
}

func TgzArgG([]string) error {
	tgzVarGzip = true
	return nil
}
