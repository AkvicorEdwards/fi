package def

import (
	"fmt"
	"github.com/AkvicorEdwards/encrypt"
	"github.com/AkvicorEdwards/util"
	"os"
	"time"
)

var Signature = [7]byte{0x17, 0x71, 0xB8, 0x01, 0x82, 0x16, 0xA7}

const (
	FlagOffsetTimestamp byte = 0
	FlagOffsetMD5       byte = 1
	FlagOffsetSHA256    byte = 2
	FlagOffsetFiletype  byte = 3
	FlagOffsetFilename  byte = 4
	FlagOffsetDescribe  byte = 5
	FlagOffsetFile      byte = 6

	LimitTimestamp = 100
	LimitMD5       = 32
	LimitSHA256    = 64
	LimitFiletype  = 64
	LimitFilename  = 32768
	LimitDescribe  = 32768
)

type Head struct {
	signature [7]byte

	headChecksum []byte // SHA256 + AES_CBC_256

	flag byte

	password []byte // limit LimitPassword
	pass     []byte // original password

	timestamp    []byte // limit LimitTimestamp
	timestampEnc bool

	md5    []byte // file MD5
	md5Enc bool

	sha256    []byte // file SHA256
	sha256Enc bool

	filetype    []byte // limit LimitFiletype
	filetypeEnc bool

	filename    []byte // limit LimitFilename
	filenameEnc bool

	describe    []byte // limit LimitDescribe
	describeEnc bool
}

func (c *Head) GetSignature() [7]byte {
	return c.signature
}

func (c *Head) SetSignature(b [7]byte) {
	c.signature = b
}

func (c *Head) GetPassword() []byte {
	return append([]byte(nil), c.password...)
}

func (c *Head) SetPassword(pass []byte, force bool) error {
	oriPassword := CalculatePassword(pass)
	// sha256 -> hashed password
	password := util.SHA256Bytes(oriPassword[:])

	if !force {
		if len(password) != len(c.password) {
			return ErrWrongPassword
		}
		for k, v := range c.password {
			if password[k] != v {
				return ErrWrongPassword
			}
		}
	}
	c.password = make([]byte, len(password))
	copy(c.password, password[:])
	c.pass = make([]byte, len(oriPassword))
	copy(c.pass, oriPassword[:])

	return nil
}

func (c *Head) PasswordValid() bool {
	password := util.SHA256Bytes(c.pass)
	if len(password) != len(c.password) {
		return false
	}
	for k, v := range c.password {
		if password[k] != v {
			return false
		}
	}
	return true
}

func (c *Head) GetTimestamp() (res uint64) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	res = util.BytesToUInt64(c.timestamp)
	return res
}

func (c *Head) SetTimeStamp(timestamp uint64) {
	c.timestamp = util.UIntToBytes(timestamp)
	//c.timestampLen = byte(len(c.timestamp))
	c.timestampEnc = false
}

func (c *Head) GetMD5() []byte {
	return append([]byte(nil), c.md5...)
}

func (c *Head) SetMD5(m []byte) {
	c.md5 = m
	c.md5Enc = false
}

func (c *Head) GetSHA256() []byte {
	return append([]byte(nil), c.sha256...)
}

func (c *Head) SetSHA256(s []byte) {
	c.sha256 = s
	c.sha256Enc = false
}

func (c *Head) GetFiletype() []byte {
	return append([]byte(nil), c.filetype...)
}

func (c *Head) SetFiletype(f []byte) {
	c.filetype = f
	c.filetypeEnc = false
}

func (c *Head) GetFilename() []byte {
	return append([]byte(nil), c.filename...)
}

func (c *Head) SetFilename(f []byte) {
	c.filename = f
	c.filenameEnc = false
}

func (c *Head) GetDescribe() []byte {
	return append([]byte(nil), c.describe...)
}

func (c *Head) SetDescribe(d []byte) {
	c.describe = d
	c.describeEnc = false
}

// Calculate Head checksum
func (c *Head) CalculateHeadCheckSum(checkEncryption bool) (err error) {
	if checkEncryption {
		err = c.Encrypt()
		if err != nil {
			return err
		}
	}
	t := c.EtcBytes()
	hsh := util.SHA256Bytes(t)
	enc, err := encrypt.AesCBCEncrypt(hsh[:], c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	c.headChecksum = enc
	return nil
}

func (c *Head) VerifyHead() bool {
	t := c.EtcBytes()
	hsh := util.SHA256Bytes(t)
	enc, err := encrypt.AesCBCEncrypt(hsh[:], c.pass, c.pass[:16])
	if err != nil {
		return false
	}
	if len(enc) != len(c.headChecksum) {
		return false
	}
	for k, v := range enc {
		if c.headChecksum[k] != v {
			return false
		}
	}
	return true
}

// Set File Encrypted Flag as true
func (c *Head) SetFileEncrypted() {
	c.SetFlag(FlagOffsetFile, true)
}

// Set File Encrypted Flag as false
func (c *Head) SetFileDecrypted() {
	c.SetFlag(FlagOffsetFile, false)
}

// Set Flag
func (c *Head) SetFlag(bit byte, set bool) {
	util.BitSet(&c.flag, bit, set)
}

func (c *Head) GetFlag(bit byte) bool {
	return (c.flag>>bit)&1 == 1
}

func (c *Head) ApplyFlagToEnc() {
	if (c.flag>>FlagOffsetTimestamp)&1 == 1 {
		c.timestampEnc = true
	}
	if (c.flag>>FlagOffsetMD5)&1 == 1 {
		c.md5Enc = true
	}
	if (c.flag>>FlagOffsetSHA256)&1 == 1 {
		c.sha256Enc = true
	}
	if (c.flag>>FlagOffsetFiletype)&1 == 1 {
		c.filetypeEnc = true
	}
	if (c.flag>>FlagOffsetFilename)&1 == 1 {
		c.filenameEnc = true
	}
	if (c.flag>>FlagOffsetDescribe)&1 == 1 {
		c.describeEnc = true
	}
}

func (c *Head) NeedPassword() bool {
	if (c.flag>>FlagOffsetTimestamp)&1 == 1 {
		return true
	}
	if (c.flag>>FlagOffsetMD5)&1 == 1 {
		return true
	}
	if (c.flag>>FlagOffsetSHA256)&1 == 1 {
		return true
	}
	if (c.flag>>FlagOffsetFiletype)&1 == 1 {
		return true
	}
	if (c.flag>>FlagOffsetFilename)&1 == 1 {
		return true
	}
	if (c.flag>>FlagOffsetDescribe)&1 == 1 {
		return true
	}
	return false
}

// Check whether "flag" and "c.*Enc" match
func (c *Head) VerifyEncrypt() (err error) {
	if ((c.flag>>FlagOffsetTimestamp)&1 == 1) != c.timestampEnc {
		return ErrCheckEncrypt
	}
	if ((c.flag>>FlagOffsetMD5)&1 == 1) != c.md5Enc {
		return ErrCheckEncrypt
	}
	if ((c.flag>>FlagOffsetSHA256)&1 == 1) != c.sha256Enc {
		return ErrCheckEncrypt
	}
	if ((c.flag>>FlagOffsetFiletype)&1 == 1) != c.filenameEnc {
		return ErrCheckEncrypt
	}
	if ((c.flag>>FlagOffsetFilename)&1 == 1) != c.filenameEnc {
		return ErrCheckEncrypt
	}
	if ((c.flag>>FlagOffsetDescribe)&1 == 1) != c.describeEnc {
		return ErrCheckEncrypt
	}
	return nil
}

func (c *Head) Encrypted() bool {
	if c.TimestampEncrypted() {
		return true
	}
	if c.MD5Encrypted() {
		return true
	}
	if c.SHA256Encrypted() {
		return true
	}
	if c.FiletypeEncrypted() {
		return true
	}
	if c.FilenameEncrypted() {
		return true
	}
	if c.DescribeEncrypted() {
		return true
	}
	return false
}

// Encrypt Head
func (c *Head) Encrypt() (err error) {
	if (c.flag>>FlagOffsetTimestamp)&1 == 1 {
		err = c.EncryptTimestamp()
		if err != nil {
			return err
		}
	}
	if (c.flag>>FlagOffsetMD5)&1 == 1 {
		err = c.EncryptMD5()
		if err != nil {
			return err
		}
	}
	if (c.flag>>FlagOffsetSHA256)&1 == 1 {
		err = c.EncryptSHA256()
		if err != nil {
			return err
		}
	}
	if (c.flag>>FlagOffsetFiletype)&1 == 1 {
		err = c.EncryptFiletype()
		if err != nil {
			return err
		}
	}
	if (c.flag>>FlagOffsetFilename)&1 == 1 {
		err = c.EncryptFilename()
		if err != nil {
			return err
		}
	}
	if (c.flag>>FlagOffsetDescribe)&1 == 1 {
		err = c.EncryptDescribe()
		if err != nil {
			return err
		}
	}
	return nil
}

// Decrypt Head
func (c *Head) Decrypt() (err error) {
	err = c.DecryptTimestamp()
	if err != nil {
		return err
	}
	err = c.DecryptMD5()
	if err != nil {
		return err
	}
	err = c.DecryptSHA256()
	if err != nil {
		return err
	}
	err = c.DecryptFiletype()
	if err != nil {
		return err
	}
	err = c.DecryptFilename()
	if err != nil {
		return err
	}
	err = c.DecryptDescribe()
	if err != nil {
		return err
	}
	return nil
}

func (c *Head) TimestampEncrypted() bool {
	return c.timestampEnc
}

// Encrypt Timestamp
func (c *Head) EncryptTimestamp() (err error) {
	if c.TimestampEncrypted() {
		return nil
	}
	if len(c.pass) < 16 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCEncrypt(c.timestamp, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > 255 {
		return ErrErrorLen
	}
	c.timestampEnc = true
	c.timestamp = t
	return nil
}

// Decrypt Timestamp
func (c *Head) DecryptTimestamp() (err error) {
	if !c.TimestampEncrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCDecrypt(c.timestamp, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > LimitTimestamp {
		return ErrErrorLen
	}
	c.timestampEnc = false
	c.timestamp = t
	return nil
}

func (c *Head) MD5Encrypted() bool {
	return c.md5Enc
}

// Encrypt MD5
func (c *Head) EncryptMD5() (err error) {
	if c.MD5Encrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCEncrypt(c.md5, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > 255 {
		return ErrErrorLen
	}
	c.md5Enc = true
	c.md5 = t
	return nil
}

// Decrypt MD5
func (c *Head) DecryptMD5() (err error) {
	if !c.MD5Encrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCDecrypt(c.md5, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > LimitMD5 {
		return ErrErrorLen
	}
	c.md5Enc = false
	c.md5 = t
	return nil
}

func (c *Head) SHA256Encrypted() bool {
	return c.sha256Enc
}

// Encrypt SHA256
func (c *Head) EncryptSHA256() (err error) {
	if c.SHA256Encrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCEncrypt(c.sha256, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > 255 {
		return ErrErrorLen
	}
	c.sha256Enc = true
	c.sha256 = t
	return nil
}

// Decrypt SHA256
func (c *Head) DecryptSHA256() (err error) {
	if !c.SHA256Encrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCDecrypt(c.sha256, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > LimitSHA256 {
		return ErrErrorLen
	}
	c.sha256Enc = false
	c.sha256 = t
	return nil
}

func (c *Head) FiletypeEncrypted() bool {
	return c.filetypeEnc
}

// Encrypt Filetype
func (c *Head) EncryptFiletype() (err error) {
	if c.FiletypeEncrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCEncrypt(c.filetype, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > 255 {
		return ErrErrorLen
	}
	c.filetypeEnc = true
	c.filetype = t
	return nil
}

// Decrypt Filetype
func (c *Head) DecryptFiletype() (err error) {
	if !c.FiletypeEncrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCDecrypt(c.filetype, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > LimitFiletype {
		return ErrErrorLen
	}
	c.filetypeEnc = false
	c.filetype = t
	return nil
}

func (c *Head) FilenameEncrypted() bool {
	return c.filenameEnc
}

// Encrypt Filename
func (c *Head) EncryptFilename() (err error) {
	if c.FilenameEncrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCEncrypt(c.filename, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > 65535 {
		return ErrErrorLen
	}
	c.filenameEnc = true
	c.filename = t
	return nil
}

// Decrypt Filename
func (c *Head) DecryptFilename() (err error) {
	if !c.FilenameEncrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCDecrypt(c.filename, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > LimitFilename {
		return ErrErrorLen
	}
	c.filenameEnc = false
	c.filename = t
	return nil
}

func (c *Head) DescribeEncrypted() bool {
	return c.describeEnc
}

// Encrypt Describe
func (c *Head) EncryptDescribe() (err error) {
	if c.DescribeEncrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCEncrypt(c.describe, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > 65535 {
		return ErrErrorLen
	}
	c.describeEnc = true
	c.describe = t
	return nil
}

// Decrypt Describe
func (c *Head) DecryptDescribe() (err error) {
	if !c.DescribeEncrypted() {
		return nil
	}
	if len(c.pass) == 0 {
		return ErrEmptyPassword
	}
	var t []byte
	t, err = encrypt.AesCBCDecrypt(c.describe, c.pass, c.pass[:16])
	if err != nil {
		return err
	}
	if len(t) > LimitDescribe {
		return ErrErrorLen
	}
	c.describeEnc = false
	c.describe = t
	return nil
}

// Convert Head to Bytes
func (c *Head) Bytes() []byte {
	return util.BytesCombine(c.signature[:], []byte{byte(len(c.headChecksum))}, c.headChecksum, []byte{c.flag},
		[]byte{byte(len(c.password))}, c.password, []byte{byte(len(c.timestamp))}, c.timestamp,
		[]byte{byte(len(c.md5))}, c.md5, []byte{byte(len(c.sha256))}, c.sha256,
		[]byte{byte(len(c.filetype))}, c.filetype,
		util.UIntToBytes(uint16(len(c.filename))), c.filename,
		util.UIntToBytes(uint16(len(c.describe))), c.describe)
}

// Convert Head to Bytes, except 'signature' and 'headChecksum'
func (c *Head) EtcBytes() []byte {
	return util.BytesCombine([]byte{c.flag}, []byte{byte(len(c.password))}, c.password,
		[]byte{byte(len(c.timestamp))}, c.timestamp, []byte{byte(len(c.md5))}, c.md5,
		[]byte{byte(len(c.sha256))}, c.sha256, []byte{byte(len(c.filetype))}, c.filetype,
		util.UIntToBytes(uint16(len(c.filename))), c.filename,
		util.UIntToBytes(uint16(len(c.describe))), c.describe)
}

func (c *Head) Write(fi *os.File) error {
	err := c.Encrypt()
	if err != nil {
		return err
	}
	bs := c.Bytes()
	_, err = fi.Write(bs)
	if err != nil {
		return err
	}
	bsh := util.SHA256Bytes(bs)
	_, err = fi.Write(bsh[:])
	if err != nil {
		return err
	}
	return nil
}

func (c *Head) Read(fi *os.File) error {
	var (
		n   int
		err error
	)
	// signature
	signature := [7]byte{}
	n, err = fi.Read(signature[:])
	if err != nil || n != 7 {
		return ErrRead
	}
	for k, v := range c.signature {
		if signature[k] != v {
			return ErrSignature
		}
	}
	// head checksum
	headChecksumLen := make([]byte, 1)
	n, err = fi.Read(headChecksumLen)
	if err != nil || n != 1 {
		return ErrRead
	}
	c.headChecksum = make([]byte, headChecksumLen[0])
	n, err = fi.Read(c.headChecksum)
	if err != nil || n != int(headChecksumLen[0]) {
		return ErrRead
	}
	// flag
	flag := make([]byte, 1)
	n, err = fi.Read(flag)
	if err != nil || n != 1 {
		return ErrRead
	}
	c.flag = flag[0]
	// password
	passwordLen := make([]byte, 1)
	n, err = fi.Read(passwordLen)
	if err != nil || n != 1 {
		return ErrRead
	}
	c.password = make([]byte, passwordLen[0])
	n, err = fi.Read(c.password)
	if err != nil || n != int(passwordLen[0]) {
		return ErrRead
	}
	// timestamp
	timestampLen := make([]byte, 1)
	n, err = fi.Read(timestampLen)
	if err != nil || n != 1 {
		return ErrRead
	}
	c.timestamp = make([]byte, timestampLen[0])
	n, err = fi.Read(c.timestamp)
	if err != nil || n != int(timestampLen[0]) {
		return ErrRead
	}
	// md5
	md5Len := make([]byte, 1)
	n, err = fi.Read(md5Len)
	if err != nil || n != 1 {
		return ErrRead
	}
	c.md5 = make([]byte, md5Len[0])
	n, err = fi.Read(c.md5)
	if err != nil || n != int(md5Len[0]) {
		return ErrRead
	}
	// sha256
	sha256Len := make([]byte, 1)
	n, err = fi.Read(sha256Len)
	if err != nil || n != 1 {
		return ErrRead
	}
	c.sha256 = make([]byte, sha256Len[0])
	n, err = fi.Read(c.sha256)
	if err != nil || n != int(sha256Len[0]) {
		return ErrRead
	}
	// filetype
	filetypeLen := make([]byte, 1)
	n, err = fi.Read(filetypeLen)
	if err != nil || n != 1 {
		return ErrRead
	}
	c.filetype = make([]byte, filetypeLen[0])
	n, err = fi.Read(c.filetype)
	if err != nil || n != int(filetypeLen[0]) {
		return ErrRead
	}
	// filename
	filenameLen := make([]byte, 2)
	n, err = fi.Read(filenameLen)
	if err != nil || n != 2 {
		return ErrRead
	}
	c.filename = make([]byte, util.BytesToUInt16(filenameLen))
	n, err = fi.Read(c.filename)
	if err != nil || n != int(util.BytesToUInt16(filenameLen)) {
		return ErrRead
	}
	// describe
	describeLen := make([]byte, 2)
	n, err = fi.Read(describeLen)
	if err != nil || n != 2 {
		return ErrRead
	}
	c.describe = make([]byte, util.BytesToUInt16(describeLen))
	n, err = fi.Read(c.describe)
	if err != nil || n != int(util.BytesToUInt16(describeLen)) {
		return ErrRead
	}

	c.ApplyFlagToEnc()

	bsh := make([]byte, 32)
	n, err = fi.Read(bsh)
	if err != nil || n != 32 {
		return ErrRead
	}
	bs := util.SHA256Bytes(c.Bytes())
	for k, v := range bsh {
		if bs[k] != v {
			return ErrRead
		}
	}
	return nil
}

func (c *Head) UpdatePassword() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = ErrInput
		}
	}()
	choose := ""
	err = c.SetPassword([]byte(""), false)
	if err == nil {
		_ = c.Decrypt()
	}
	if c.Encrypted() {
		fmt.Println("Head is encrypted, Please enter old password.")
		err = c.SetPassword([]byte(util.Input("")), false)
		if err != nil {
			fmt.Println("Wrong Password")
			return err
		}
		_ = c.Decrypt()
	}
	if c.Encrypted() {
		return ErrBrokenHead
	}

	fmt.Println("Input New Password [Y/n]")
	_, _ = fmt.Scanln(&choose)
	if choose != "n" && choose != "N" {
		err = c.SetPassword([]byte(util.Input("")), true)
		if err != nil {
			fmt.Println("Update password failed")
			return err
		}
	}
	return nil
}

func (c *Head) Input(force bool) (err error) {
	backup := c.Bytes()
	defer func() {
		if err != nil {
			err2 := c.ReadFromBytes(backup)
			if err2 != nil {
				fmt.Println("Head Broken")
			}
		}
	}()
	defer func() {
		if r := recover(); r != nil {
			err = ErrInput
		}
	}()
	choose := ""

	fmt.Println("Update Password [Y/n]")
	_, _ = fmt.Scanln(&choose)
	if choose != "n" && choose != "N" {
		err = c.UpdatePassword()
		if err != nil {
			fmt.Println("Error")
			return err
		}
	}
	choose = ""
	fmt.Printf("Timestamp:[%v] MD5:[%v] SHA256:[%v] Filetype:[%v] Filename:[%v] Describe:[%v] File:[%v]\n",
		(c.flag>>FlagOffsetTimestamp)&1, (c.flag>>FlagOffsetMD5)&1, (c.flag>>FlagOffsetSHA256)&1,
		(c.flag>>FlagOffsetFiletype)&1, (c.flag>>FlagOffsetFilename)&1, (c.flag>>FlagOffsetDescribe)&1,
		(c.flag>>FlagOffsetFile)&1)
	fmt.Println("Encrypt info/file [Y/n]")
	_, _ = fmt.Scanln(&choose)
	if choose != "n" && choose != "N" {
		choose = ""
		fmt.Println("Encrypt Timestamp [Y/n]")
		_, _ = fmt.Scanln(&choose)
		if choose != "n" && choose != "N" {
			c.SetFlag(FlagOffsetTimestamp, true)
		}
		choose = ""
		fmt.Println("Encrypt MD5 [Y/n]")
		_, _ = fmt.Scanln(&choose)
		if choose != "n" && choose != "N" {
			c.SetFlag(FlagOffsetMD5, true)
		}
		choose = ""
		fmt.Println("Encrypt SHA256 [Y/n]")
		_, _ = fmt.Scanln(&choose)
		if choose != "n" && choose != "N" {
			c.SetFlag(FlagOffsetSHA256, true)
		}
		choose = ""
		fmt.Println("Encrypt Filetype [Y/n]")
		_, _ = fmt.Scanln(&choose)
		if choose != "n" && choose != "N" {
			c.SetFlag(FlagOffsetFiletype, true)
		}
		choose = ""
		fmt.Println("Encrypt Filename [Y/n]")
		_, _ = fmt.Scanln(&choose)
		if choose != "n" && choose != "N" {
			c.SetFlag(FlagOffsetFilename, true)
		}
		choose = ""
		fmt.Println("Encrypt Describe [Y/n]")
		_, _ = fmt.Scanln(&choose)
		if choose != "n" && choose != "N" {
			c.SetFlag(FlagOffsetDescribe, true)
		}
		choose = ""
		fmt.Println("Encrypt File [Y/n]")
		_, _ = fmt.Scanln(&choose)
		if choose != "n" && choose != "N" {
			c.SetFlag(FlagOffsetFile, true)
		}
		fmt.Printf("Timestamp:[%v] MD5:[%v] SHA256:[%v] Filetype:[%v] Filename:[%v] Describe:[%v] File:[%v]\n",
			(c.flag>>FlagOffsetTimestamp)&1, (c.flag>>FlagOffsetMD5)&1, (c.flag>>FlagOffsetSHA256)&1,
			(c.flag>>FlagOffsetFiletype)&1, (c.flag>>FlagOffsetFilename)&1, (c.flag>>FlagOffsetDescribe)&1,
			(c.flag>>FlagOffsetFile)&1)
	}
	choose = ""
	fmt.Println("Input Timestamp(s) [G/y/n]")
	_, _ = fmt.Scanln(&choose)
	if choose == "n" || choose == "N" {
	} else if choose == "y" || choose == "Y" {
		if c.TimestampEncrypted() {
			err = c.DecryptTimestamp()
			if err != nil {
				if force {
					c.SetTimeStamp(0)
				} else {
					return err
				}
			}
		}
		var t uint64
		fmt.Printf("Old: [%d]\n", c.GetTimestamp())
		fmt.Print("New: ")
		_, err = fmt.Scanln(&t)
		for err != nil {
			fmt.Print("New: ")
			_, err = fmt.Scanln(&t)
		}
		c.timestampEnc = false
		c.SetTimeStamp(t)
	} else {
		c.timestampEnc = false
		c.SetTimeStamp(uint64(time.Now().Unix()))
	}
	choose = ""
	fmt.Println("Input Filetype [Y/n]")
	_, _ = fmt.Scanln(&choose)
	if choose != "n" && choose != "N" {
		if c.FiletypeEncrypted() {
			err = c.DecryptFiletype()
			if err != nil {
				if force {
					c.SetFiletype([]byte{})
				} else {
					return err
				}
			}
		}
		c.filetypeEnc = false
		c.SetFiletype([]byte(util.Input(string(c.filetype))))
	}
	choose = ""
	fmt.Println("Input Filename [Y/n]")
	_, _ = fmt.Scanln(&choose)
	if choose != "n" && choose != "N" {
		if c.FilenameEncrypted() {
			err = c.DecryptFilename()
			if err != nil {
				if force {
					c.SetFilename([]byte{})
				} else {
					return err
				}
			}
		}
		c.filenameEnc = false
		c.SetFilename([]byte(util.Input(string(c.filename))))
	}
	choose = ""
	fmt.Println("Input Describe [Y/n]")
	_, _ = fmt.Scanln(&choose)
	if choose != "n" && choose != "N" {
		if c.DescribeEncrypted() {
			err = c.DecryptDescribe()
			if err != nil {
				if force {
					c.SetDescribe([]byte{})
				} else {
					return err
				}
			}
		}
		c.describeEnc = false
		c.SetDescribe([]byte(util.Input(string(c.describe))))
	}
	return nil
}

// Return a new Head
func NewHead() (head *Head) {
	head = &Head{
		signature:    Signature,
		headChecksum: make([]byte, 0),
		flag:         0,
		password:     make([]byte, 0),
		pass:         make([]byte, 0),
		timestamp:    make([]byte, 0),
		timestampEnc: false,
		md5:          make([]byte, 0),
		md5Enc:       false,
		sha256:       make([]byte, 0),
		sha256Enc:    false,
		filetype:     make([]byte, 0),
		filetypeEnc:  false,
		filename:     make([]byte, 0),
		filenameEnc:  false,
		describe:     make([]byte, 0),
		describeEnc:  false,
	}
	_ = head.SetPassword([]byte(""), true)
	return head
}

// convert bytes to head
func (c *Head)ReadFromBytes(data []byte) (err error) {
	if len(data) < 7+1 {
		return nil
	}
	copy(c.signature[:], data)
	data = data[7:]

	headChecksumLen := data[0]
	data = data[1:]
	if len(data) < int(headChecksumLen)+1+1 {
		return nil
	}
	c.headChecksum = data[:headChecksumLen]
	data = data[headChecksumLen:]

	c.flag = data[0]
	data = data[1:]

	passwordLen := data[0]
	data = data[1:]
	if len(data) < int(passwordLen)+1 {
		return nil
	}
	c.password = data[:passwordLen]
	data = data[passwordLen:]

	timestampLen := data[0]
	data = data[1:]
	if len(data) < int(timestampLen)+1 {
		return nil
	}
	c.timestamp = data[:timestampLen]
	data = data[timestampLen:]
	if (c.flag>>FlagOffsetTimestamp)&1 == 1 {
		c.timestampEnc = true
	}

	md5Len := data[0]
	data = data[1:]
	if len(data) < int(md5Len)+1 {
		return nil
	}
	c.md5 = data[:md5Len]
	data = data[md5Len:]
	if (c.flag>>FlagOffsetMD5)&1 == 1 {
		c.md5Enc = true
	}

	sha256Len := data[0]
	data = data[1:]
	if len(data) < int(sha256Len)+2 {
		return nil
	}
	c.sha256 = data[:sha256Len]
	data = data[sha256Len:]
	if (c.flag>>FlagOffsetSHA256)&1 == 1 {
		c.sha256Enc = true
	}

	filetypeLen := data[0]
	data = data[1:]
	if len(data) < int(filetypeLen)+2 {
		return nil
	}
	c.filetype = data[:filetypeLen]
	data = data[filetypeLen:]
	if (c.flag>>FlagOffsetFiletype)&1 == 1 {
		c.filetypeEnc = true
	}

	filenameLen := util.BytesToUInt16(data[:2])
	data = data[2:]
	if len(data) < int(filenameLen)+2 {
		return nil
	}
	c.filename = data[:filenameLen]
	data = data[filenameLen:]
	if (c.flag>>FlagOffsetFilename)&1 == 1 {
		c.filenameEnc = true
	}

	describeLen := util.BytesToUInt16(data[:2])
	data = data[2:]
	if len(data) < int(describeLen) {
		return nil
	}
	c.describe = data[:describeLen]
	if (c.flag>>FlagOffsetDescribe)&1 == 1 {
		c.describeEnc = true
	}

	c.ApplyFlagToEnc()
	return nil
}
