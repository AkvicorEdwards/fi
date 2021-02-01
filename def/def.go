package def

import "github.com/AkvicorEdwards/util"

var Salt = "x/&2>?h*7s,Gj!l"

func CalculatePassword(password []byte) []byte {
	// add salt
	saltPassword := util.BytesCombine(password, []byte(Salt))
	// sha256 -> password
	oriPassword := util.SHA256Bytes(saltPassword)
	return oriPassword[:]
}
