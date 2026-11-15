// capabilities is an image-local preflight marker, not an image attestation.
package main

import (
	"fmt"
	"github.com/ljfranklin/terraform-resource/verified"
)

func main() { fmt.Println(verified.Protocol) }
