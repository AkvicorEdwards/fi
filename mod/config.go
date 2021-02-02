package mod

import (
	"errors"
	"fi/def"
	"fmt"
	"github.com/AkvicorEdwards/arg"
	"github.com/AkvicorEdwards/encrypt"
	"github.com/AkvicorEdwards/util"
	"io"
	"os"
)

/*
config edit config file
	size = 1 [filename]
	-p password
 */

func AddConfig(order int) (err error) {
	err = arg.AddCommand([]string{"config"}, order, 1, "Config file",
		"Config file", "", "[filename]", Config, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"config", "-p"}, 10, 1, 10, "If the information is encrypted,\n"+
		"use this specified password", "Specify password", "",
		"[password]", ConfigArgP, nil)
	if err != nil {
		return err
	}
	err = AddOptionKeepTemporaryFiles([]string{"config"}, 50, 100)
	if err != nil {
		return err
	}
	err = AddOptionDisplayLog([]string{"config"}, 60, 200)
	if err != nil {
		return err
	}

	return nil
}

var ErrConfigWrongPassword = errors.New("wrong password")

var configVarPassword = ""

func Config(str []string) error {
	filename := str[1]
	tempFilename := "~" + filename + ".dec"
	head := def.NewHead()

	// read head
	// export and decrypt file to tempFile
	created := false
	defer func() {
		if created {
			Remove("~" + filename + ".dec")
		}
	}()
	createdEnc := false
	defer func() {
		if createdEnc {
			Remove("~"+"~" + filename + ".dec"+".enc")
		}
	}()
	err := func() error {
		file, err := os.Open(filename)
		if err != nil {
			fmt.Println("Cannot read file:", filename)
			return err
		}
		defer Close(file)
		err = head.Read(file)
		if err != nil {
			fmt.Println("Invalid File")
			return err
		}
		fileEncrypted := head.GetFlag(def.FlagOffsetFile)
		originalPassword := head.GetPassword()
		err = head.SetPassword([]byte(configVarPassword), false)
		if err != nil {
			choose := ""
			fmt.Println("Input Password [Y/n]")
			_, _ = fmt.Scanln(&choose)
			if choose != "n" && choose != "N" {
				err = head.SetPassword([]byte(util.Input("")), false)
				if err != nil {
					return ErrConfigWrongPassword
				}
			} else {
				return ErrConfigWrongPassword
			}
		}
		err = head.Input(false)
		if err != nil {
			fmt.Println("Input Error")
			return err
		}
		err = head.Decrypt()
		if err != nil {
			return err
		}
		ShowHeadInfo(head)
		target, err := os.Create(tempFilename)
		if err != nil {
			return err
		}
		defer func() {
			created = true
			Close(target)
		}()
		// Export file
		if fileEncrypted {
			err = encrypt.AesCTRDecryptFileIO(file, target, originalPassword, originalPassword[:16])
			if err != nil {
				return err
			}
		} else {
			_, err = io.Copy(target, file)
			if err != nil {
				return err
			}
		}
		// ReEncrypt
		if head.GetFlag(def.FlagOffsetFile) {
			createdEnc = true
			err = encrypt.AesCTREncryptFile(tempFilename, "~"+tempFilename+".enc",
				head.GetPassword(), head.GetPassword()[:16])
			if err != nil {
				return err
			}
			tempFilename = "~"+tempFilename+".enc"
		}
		return nil
	}()
	if err != nil {
		Println(err)
		return err
	}

	// Calculate MD5
	err = nil
	md5 := func() []byte {
		var f [16]byte
		f, err = util.MD5File(tempFilename)
		if err != nil {
			return []byte{}
		}
		return f[:]
	}()
	if err != nil {
		Println(err)
		return err
	}
	// Calculate SHA256
	err = nil
	sha256 := func() []byte {
		var f [32]byte
		f, err = util.SHA256File(tempFilename)
		if err != nil {
			return []byte{}
		}
		return f[:]
	}()
	if err != nil {
		Println(err)
		return err
	}
	head.SetMD5(md5)
	head.SetSHA256(sha256)

	err = head.Encrypt()
	if err != nil {
		return err
	}
	err = os.Remove(filename)
	if err != nil {
		return err
	}

	target, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer Close(target)
	err = head.Write(target)
	if err != nil {
		Println(err)
		return err
	}
	origin, err := os.Open(tempFilename)
	if err != nil {
		Println(err)
		return err
	}
	defer Close(origin)

	_, err = io.Copy(target, origin)
	if err != nil {
		Println(err)
		return err
	}
	fmt.Println("Finished")
	return nil
}

func ConfigArgP(args []string) error {
	configVarPassword = args[1]
	return nil
}
