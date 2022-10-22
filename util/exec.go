package util

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

func Exec(command string, args string) (stdout, stderr string, err error) {
	logrus.Tracef("EXEC: %v %v", command, args)

	cmd := exec.Command(command, strings.Split(args, " ")...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err = cmd.Run()
	stdout = outb.String()
	stderr = errb.String()

	return
}
