// +build linux darwin
package priv

import "os/exec"

type commandFactory struct {}

func NewCommandFactory() *commandFactory {
	return &commandFactory{}
}

func (f commandFactory) NewCommand(cmd string, args ...string) (*exec.Cmd, error) {
	return exec.Command(cmd, args...), nil
}
