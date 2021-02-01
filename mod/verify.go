package mod

import (
	"fi/def"
	"fmt"
	"github.com/AkvicorEdwards/arg"
	"github.com/AkvicorEdwards/util"
	"os"
)

/*
verify verify file hash
	size = 1 [filename]
	-p password
	-m md5
	-s sha256
	[default] -ms
*/

func AddVerify(order int) (err error) {
	err = arg.AddCommand([]string{"verify"}, order, 1, "Verify file",
		"Verify file", "", "[filename]", Verify, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"verify", "-p"}, 10, 1, 10, "If the information is encrypted,\n"+
		"use this specified password", "Specify password", "",
		"[password]", VerifyArgP, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"verify", "-m"}, 20, 0, 10, "Verify MD5",
		"Verify MD5", "", "", VerifyArgM, nil)
	if err != nil {
		return err
	}
	err = arg.AddOption([]string{"verify", "-s"}, 30, 0, 10, "Verify SHA256",
		"Verify SHA256", "", "", VerifyArgS, nil)
	if err != nil {
		return err
	}
	err = AddOptionDisplayLog([]string{"verify"}, 60, 200)
	if err != nil {
		return err
	}
	return nil
}

var verifyVarPassword = ""
var verifyVarMD5 = false
var verifyVarSHA256 = false

func Verify(str []string) error {
	if !verifyVarMD5 && !verifyVarSHA256 {
		verifyVarMD5 = true
		verifyVarSHA256 = true
	}
	filename := str[1]
	file, err := os.Open(filename)
	if err != nil {
		Println(err)
		return err
	}
	defer Close(file)
	head := def.NewHead()
	err = head.Read(file)
	if err != nil {
		fmt.Println("Invalid File")
		Println(err)
		return err
	}
	L := int64(len(head.Bytes()))
	wrongPassword := false
	err = head.SetPassword([]byte(verifyVarPassword), false)
	if err != nil {
		wrongPassword = true
	}

	if verifyVarMD5 {
		result := ""
		func() {
			if head.MD5Encrypted() && wrongPassword {
				result = "Encrypted"
				return
			}
			err = head.DecryptMD5()
			if err != nil {
				result = "Encrypted"
				return
			}
			md5 := head.GetMD5()
			m5, err := util.MD5FileIO(file)
			if err != nil || len(md5) != len(m5) {
				result = "Failure"
				return
			}
			for k, v := range m5 {
				if md5[k] != v {
					result = "Failure"
					return
				}
			}
			result = "Pass"
		}()
		fmt.Printf("Verify MD5:    [%s]\n", result)
	}

	if verifyVarSHA256 {
		if verifyVarMD5 {
			_, err = file.Seek(L, 0)
			if err != nil {
				return err
			}
		}
		result := ""
		func() {
			if head.SHA256Encrypted() && wrongPassword {
				result = "Encrypted"
				return
			}
			err = head.DecryptSHA256()
			if err != nil {
				result = "Encrypted"
				return
			}
			sha256 := head.GetSHA256()
			s6, err := util.SHA256FileIO(file)
			if err != nil || len(sha256) != len(s6) {
				result = "Failure"
				return
			}
			for k, v := range s6 {
				if sha256[k] != v {
					result = "Failure"
					return
				}
			}
			result = "Pass"
		}()
		fmt.Printf("Verify SHA256: [%s]\n", result)
	}

	return nil
}

func VerifyArgP(args []string) error {
	verifyVarPassword = args[1]
	return nil
}

func VerifyArgM([]string) error {
	verifyVarMD5 = true
	return nil
}

func VerifyArgS([]string) error {
	verifyVarSHA256 = true
	return nil
}
