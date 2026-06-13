package core

import "fmt"

const banner = `                    
 _____ _____ _____ _____ _____ _____ 
|   __|   __| __  | __  |  |  |     |
|   __|   __|    -|    -|  |  | | | |
|__|  |_____|__|__|__|__|_____|_|_|_|
                                     

Ferrum Windows Vulnerability Research Framework

Build : %s
Author: Kernelstub

#########################################

`

func Banner(build string) string {
	return fmt.Sprintf(banner, build)
}
