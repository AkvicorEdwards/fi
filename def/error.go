package def

import "errors"

var ErrErrorLen = errors.New("error len")
var ErrEmptyPassword = errors.New("empty password")
var ErrWrongPassword = errors.New("wrong password")
var ErrBrokenHead = errors.New("broken head")
var ErrInput = errors.New("error input")
var ErrCheckEncrypt = errors.New("check encrypt")
var ErrRead = errors.New("error read")
var ErrSignature = errors.New("error signature")
