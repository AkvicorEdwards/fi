package mod

import (
	"errors"
	"fi/def"
	"fmt"
	"github.com/AkvicorEdwards/arg"
	"github.com/AkvicorEdwards/encrypt"
	"github.com/AkvicorEdwards/press"
	"github.com/AkvicorEdwards/util"
	"io"
	"os"
	"strings"
)

/*
if is "fi", show info
else, convert to "fi"

size = 1 [filename]

-p password (valid for Fi file) (valid for normal file)
-r target if dir (valid for normal file)
-z gzip file (valid for normal file)
-o out file (valid for Fi file) (valid for normal file)

--log Display all logs when the program is running
--keep Keep all temporary files
 */

func AddFi() (err error) {
	arg.RootCommand.Describe = ""
	arg.RootCommand.Size = 1
	arg.RootCommand.DescribeBrief = ""
	arg.RootCommand.Usage = "[filename]"
	arg.RootCommand.Executor = Fi

	err = arg.AddOption([]string{"-p"}, 10, 1, 10, "If the information is encrypted,\n" +
		"use this specified password", "Specify password", "",
		"[password]", FiArgP, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"-r"}, 30, 0, 10, "If the target is folder: Pack", "target is folder", "",
		"", FiArgR, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"-o"}, 20, 1, 10,
		"If the target filename is a normal file: Specify the file name after conversion\n"+
			"If the target filename is a Fi file: Extract the file to this file",
		"Specify the output file name", "", "[filename]", FiArgO, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"-z"}, 40, 0, 10, "Gzip target file",
		"gzip", "", "", FiArgZ, nil)
	if err != nil {
		return err
	}
	err = AddOptionKeepTemporaryFiles([]string{}, 50, 100)
	if err != nil {
		return err
	}
	err = AddOptionDisplayLog([]string{}, 60, 200)
	if err != nil {
		return err
	}

	return nil
}

var ErrNotDir = errors.New("not dir")
var ErrCreateFile = errors.New("error create file")

var fiVarPassword = ""
var fiVarIsDir = false
var fiVarGzip = false
var fiVarTargetFile = ""

func Fi(args []string) error {
	realFilename := args[1]
	filename := args[1]
	filetype := ""

	// -r
	// if is dir, tgz it
	if fiVarIsDir {
		fmt.Println("Packing and Compressing...")
		Println("Check if the file exist")
		if util.FileStat(filename) != 1 {
			fmt.Println("File does not exist or is not a directory")
			return ErrNotDir
		}
		Println("Tar...")
		tfn1 := "~"+filename+".tar"
		defer func() {
			Remove(tfn1)
		}()
		err := press.Tar([]string{filename}, "", tfn1)
		if err != nil {
			Println("Error Tar", err)
			return err
		}
		filename = "~"+filename+".tar"
		filetype += "tar "
		Println("New Filename", filename)
	}

	// open file
	if util.FileStat(filename) != 2 {
		fmt.Println("File does not exist or is not a directory")
		return ErrNotDir
	}
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Cannot find file")
		return err
	}
	ft1 := file
	defer func() {
		Println("Close file:", ft1.Name())
		err := ft1.Close()
		if err != nil {
			Println("Error Close", err)
		}
	}()

	// Read head
	hd := def.NewHead()
	err = hd.Read(file)
	// normal file
	if err != nil {
		Println("Normal File")
		Println("Reset Offset:", file.Name())
		// Reset Offset
		_, err = file.Seek(0, 0)
		if err != nil {
			return err
		}
		// Rebuild output filename
		if len(fiVarTargetFile) == 0 {
			fiVarTargetFile = realFilename + ".fi"
		}
		// Open target file
		Println("Create Target File", fiVarTargetFile)
		target, err := os.Create(fiVarTargetFile)
		if err != nil {
			Println("Error Create:", err)
			return ErrCreateFile
		}
		tf2 := target
		defer func() {
			Println("Close file:", tf2.Name())
			err := tf2.Close()
			if err != nil {
				Println("Error Close", err)
			}
		}()
		// Gzip File
		if fiVarGzip {
			fmt.Println("Compressing...")
			filename = "~"+filename+".gz"
			filetype += "gzip "
			Println("New Filename:", filename)
			tfn1 := filename
			defer func() {
				Remove(tfn1)
			}()
			err = nil
			func(){
				var tempFile *os.File
				Println("Create New File", filename)
				tempFile, err = os.Create(filename)
				if err != nil {
					Println("Error Create:", err)
					return
				}
				defer func() {
					Println("Close File:", tempFile.Name())
					err := tempFile.Close()
					if err != nil {
						Println("Error Close", err)
					}
				}()
				err = press.GzipToFileIO(file, tempFile)
				if err != nil {
					Println("Error Gzip:", err)
					return
				}
			}()
			if err != nil {
				return err
			}
		}
		Println("Input Head")
		head := def.NewHead()
		head.SetFiletype([]byte(strings.TrimSpace(filetype)))
		err = head.Input(true)
		if err != nil {
			Println("Error Input:", err)
			return err
		}
		// Encrypt File
		if head.GetFlag(def.FlagOffsetFile) {
			fmt.Println("Encrypting...")
			tfn2 := "~"+filename+".enc"
			Printf("Encrypt [%s] to [%s]\n", filename, tfn2)
			defer func() {
				Remove(tfn2)
			}()
			err = encrypt.AesCTREncryptFile(filename, tfn2,
				head.GetPassword(), head.GetPassword()[:16])
			if err != nil {
				Println("Error Encrypt:", err)
				return err
			}

			filename = "~"+filename+".enc"
			Println("New Filename:", filename)
		}
		// Calculate MD5
		err = nil
		md5 := func() []byte {
			var f [16]byte
			fmt.Println("Calculating MD5...")
			f, err = util.MD5File(filename)
			if err != nil {
				Println("Error Calc MD5", err)
				return []byte{}
			}
			return f[:]
		}()
		if err != nil {
			return err
		}
		// Calculate SHA256
		err = nil
		sha256 := func() []byte {
			var f [32]byte
			fmt.Println("Calculating SHA256...")
			f, err = util.SHA256File(filename)
			if err != nil {
				Println("Error Calc SHA256", err)
				return []byte{}
			}
			return f[:]
		}()
		if err != nil {
			return err
		}
		head.SetMD5(md5)
		head.SetSHA256(sha256)

		// Open Origin File
		Println("Open File:", filename)
		file, err = os.Open(filename)
		if err != nil {
			Println("Error Open:", filename)
			return err
		}
		defer func() {
			Println("Close file:", file.Name())
			err = file.Close()
			if err != nil {
				Println("Error Close", err)
			}
		}()
		// Build fi
		Println("Write Head")
		err = head.Write(target)
		if err != nil {
			Println("Error Write Head:", err)
			return err
		}
		Println("Write File")
		_, err = io.Copy(target, file)
		if err != nil {
			Println("Error Write File:", err)
			return err
		}
		fmt.Println("Finished")
		return nil
	}
	// "fi" file
	return fiFiFile(file, hd)
}

func fiFiFile(file *os.File, head *def.Head) error {
	err := head.SetPassword([]byte(fiVarPassword), false)
	if len(fiVarPassword) != 0  && err != nil {
		fmt.Println("Wrong Password!")
	}
	Println("Set Password:", err)

	err = head.Decrypt()
	Println("Decrypt:", err)

	ShowHeadInfo(head)

	if len(fiVarTargetFile) != 0 {
		if head.GetFlag(def.FlagOffsetFile) && !head.PasswordValid() {
			fmt.Println("Wrong Password!")
			return def.ErrWrongPassword
		}
		f, err := os.Create(fiVarTargetFile)
		if err != nil {
			Println("Error Create:", err)
			return err
		}
		defer func() {
			err = f.Close()
			if err != nil {
				Println("Error Close", f.Name())
			}
		}()
		if head.GetFlag(def.FlagOffsetFile) {
			fmt.Println("Decrypt File...")
			err = encrypt.AesCTRDecryptFileIO(file, f, head.GetPassword(), head.GetPassword()[:16])
			if err != nil {
				fmt.Println("Error Decrypt:", err)
				return nil
			}
		} else {
			_, err = io.Copy(f, file)
			if err != nil {
				fmt.Println("Error Export file")
				return nil
			}
		}
	}

	return nil
}

func FiArgP(args []string) error {
	fiVarPassword = args[1]
	return nil
}

func FiArgR([]string) error {
	fiVarIsDir = true
	return nil
}

func FiArgO(args []string) error {
	fiVarTargetFile = args[1]
	return nil
}

func FiArgZ([]string) error {
	fiVarGzip = true
	return nil
}

