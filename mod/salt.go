package mod

import (
	"fi/def"
	"fmt"
	"github.com/AkvicorEdwards/arg"
)

/*
salt  Display Salt value
 */

func AddSalt(order int) (err error) {
	err = arg.AddCommand([]string{"salt"}, order, -1, "Display Salt Value",
		"Display Salt Value", "", "", Salt, nil)
	if err != nil {
		return err
	}

	return nil
}

func Salt([]string) error {
	fmt.Printf("Salt: [%s] [%X]\n", def.Salt, []byte(def.Salt))
	return nil
}

