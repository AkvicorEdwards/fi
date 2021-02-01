package main

import (
	"fi/mod"
	"fmt"
	"github.com/AkvicorEdwards/arg"
)

func main() {
	var err error
	err = mod.AddFi()
	if err != nil {
		fmt.Println("Program crash")
		return
	}
	err = mod.AddVerify(10)
	if err != nil {
		fmt.Println("Program crash")
		return
	}
	err = mod.AddConfig(20)
	if err != nil {
		fmt.Println("Program crash")
		return
	}
	err = mod.AddTgz(30)
	if err != nil {
		fmt.Println("Program crash")
		return
	}
	err = mod.AddEnc(40)
	if err != nil {
		fmt.Println("Program crash")
		return
	}
	err = mod.AddDec(50)
	if err != nil {
		fmt.Println("Program crash")
		return
	}
	err = mod.AddSalt(60)
	if err != nil {
		fmt.Println("Program crash")
		return
	}

	arg.AddHelpCommandArg("help")
	arg.RootCommand.GenerateHelp()
	arg.EnableOptionCombination()
	err = arg.Parse()
	if err != nil && err != arg.ErrHelp{
		fmt.Println("Program crash")
		return
	}
}

