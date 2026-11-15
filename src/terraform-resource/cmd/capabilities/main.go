// capabilities is an image-local preflight marker, not an image attestation.
package main

import (
	"fmt"
	"os"

	"github.com/ljfranklin/terraform-resource/verified"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--verification-deadline" {
		fmt.Println(verified.DeadlineCapability)
		return
	}
	fmt.Println(verified.Protocol)
}
