package priv

import "os/exec"

type commandFactory struct {}

func NewCommandFactory() *commandFactory {
	return &commandFactory{}
}

//NewCommand builds an exec.Cmd that will the current impersonation token instead of the current process token, allow privilege dropping
// works by setting cmd.SysProcAttr.Token which triggers special-case syscall
// https://golang.org/src/syscall/exec_windows.go#L327
// if sys.Token != 0 {
//   err = CreateProcessAsUser(sys.Token, argv0p, argvp, sys.ProcessAttributes, sys.ThreadAttributes, true, flags, createEnvBlock(attr.Env), dirp, si, pi)
// } else {
//   err = CreateProcess(argv0p, argvp, sys.ProcessAttributes, sys.ThreadAttributes, true, flags, createEnvBlock(attr.Env), dirp, si, pi)
// }
func (f commandFactory) NewCommand(cmd string, args ...string) (*exec.Cmd, error) {
	origThread := windows.CurrentThread()

	var origToken windows.Token
	if err := windows.OpenThreadToken(origThread, windows.TOKEN_DUPLICATE, true, &origToken); err != nil {
		return nil, fmt.Errorf("OpenThreadToken: %w\n", err)
	}

	var dupToken windows.Token
	if err := windows.DuplicateTokenEx(origToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &dupToken); err != nil {
		return nil, fmt.Errorf("DuplicateTokenEx: %w\n", err)
	}

	cmd := exec.Command(name, arg...)

	cmd.SysProcAttr = &windows.SysProcAttr{
		Token: syscall.Token(dupToken),
	}

	return cmd, nil
}
