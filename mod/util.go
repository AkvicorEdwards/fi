package mod

import (
	"fi/def"
	"fmt"
	"github.com/AkvicorEdwards/arg"
	"log"
	"os"
	"time"
)

func ShowHeadInfo(head *def.Head) {
	if !head.TimestampEncrypted() {
		fmt.Printf("Timestamp:[%s] [%d]\n", time.Unix(int64(head.GetTimestamp()),
			0).Format("2006-01-02 15:04:05"), head.GetTimestamp())
	}
	if !head.MD5Encrypted() {
		fmt.Printf("MD5      :[%x]\n", head.GetMD5())
	}
	if !head.SHA256Encrypted() {
		fmt.Printf("SHA256   :[%x]\n", head.GetSHA256())
	}
	if !head.FiletypeEncrypted() {
		fmt.Printf("Filetype :[%s]\n", string(head.GetFiletype()))
	}
	if !head.FilenameEncrypted() {
		fmt.Printf("Filename :[%s]\n", string(head.GetFilename()))
	}
	if !head.DescribeEncrypted() {
		fmt.Printf("Describe :\n%s\n", string(head.GetDescribe()))
	}
}

func AddOptionDisplayLog(path []string, order, priority int) error {
	return arg.AddOption(append(path, "--log"), order, 0, priority, "Display all logs when the program is running",
		"Display all logs", "", "", ArgDisplayLog, nil)
}

var VarDisplayLog = false

func ArgDisplayLog([]string) error {
	VarDisplayLog = true
	return nil
}

func Println(v ...interface{}) {
	if VarDisplayLog {
		log.Println(v...)
	}
}

func Printf(format string, v ...interface{}) {
	if VarDisplayLog {
		log.Printf(format, v...)
	}
}

var VarKeepTemporaryFiles = false

func AddOptionKeepTemporaryFiles(path []string, order, priority int) error {
	return arg.AddOption(append(path, "--keep"), order, 0, priority, "Keep all temporary files",
		"Keep all temporary files", "", "", ArgKeepTemporaryFiles, nil)
}

func ArgKeepTemporaryFiles([]string) error {
	VarKeepTemporaryFiles = true
	return nil
}

func Remove(filename string) {
	if !VarKeepTemporaryFiles {
		Println("Remove File:", filename)
		err := os.Remove(filename)
		if err != nil {
			Println(err)
		}
	}
}

func Close(file *os.File) {
	err := file.Close()
	if err != nil {
		Printf("Cannot close file: [%s]", file.Name())
	}
}

