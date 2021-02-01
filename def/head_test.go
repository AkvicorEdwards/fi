package def

import (
	"fmt"
	"github.com/AkvicorEdwards/util"
	"testing"
	"time"
)

func TestHead(t *testing.T) {
	var err error
	hd := NewHead()
	//fmt.Printf("%-4d %8b\n", hd.flag, hd.flag)
	hd.SetFlag(FlagOffsetFilename, true)
	//fmt.Printf("%-4d %8b\n", hd.flag, hd.flag)
	hd.SetFileEncrypted()
	//fmt.Printf("%-4d %8b\n", hd.flag, hd.flag)
	err = hd.SetPassword([]byte("12345678123456781234567812345678"), true)
	if err != nil {
		t.Error(err)
	}
	hd.SetTimeStamp(uint64(time.Now().UnixNano()))
	m5 := util.MD5String("Hello world")
	hd.SetMD5(m5[:])
	s6 := util.SHA256String("Hello world")
	hd.SetSHA256(s6[:])
	hd.SetFilename([]byte("filename"))
	hd.SetDescribe([]byte("describe"))
	//fmt.Println(string(hd.filename))
	err = hd.CalculateHeadCheckSum(true)
	if err != nil {
		t.Error(err)
	}
	//fmt.Println(string(hd.filename))

	bs := hd.Bytes()
	shd := NewHead()
	err = shd.ReadFromBytes(bs)
	if err != nil {
		t.Error(err)
	}

	err = shd.SetPassword([]byte("12345678123456781234567812345678"), false)
	if err != nil {
		t.Error(err)
	}

	ans1 := fmt.Sprint(*hd)
	ans2 := fmt.Sprint(*shd)

	if ans1 != ans2 {
		fmt.Println(ans1)
		fmt.Println(ans2)
		t.Error("ans1 != ans2")
	}

	//fmt.Println(string(shd.filename))
	//fmt.Println(shd.CheckHead())
	err = shd.DecryptFilename()
	if err != nil {
		t.Error(err)
	}
	//fmt.Println(string(shd.filename))
	//fmt.Println(shd.CheckHead())
	if string(shd.filename) != "filename" {
		fmt.Println(string(shd.filename))
		t.Error("shd.filename != \"filename\"")
	}

}
