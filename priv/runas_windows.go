//+build windows

package priv

import (
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"time"
)

type runner struct {
}

func NewRunner() *runner {
	return &runner{}
}

//CommandWithToken adds a Token for the given SID to the cmd.SysProcAttr.Token
// Required to trigger special-case syscall
// https://golang.org/src/syscall/exec_windows.go#L327
// if sys.Token != 0 {
//   err = CreateProcessAsUser(sys.Token, argv0p, argvp, sys.ProcessAttributes, sys.ThreadAttributes, true, flags, createEnvBlock(attr.Env), dirp, si, pi)
// } else {
//   err = CreateProcess(argv0p, argvp, sys.ProcessAttributes, sys.ThreadAttributes, true, flags, createEnvBlock(attr.Env), dirp, si, pi)
// }
func (r *runner) RunAs(sid string) error {
	var matchingPID uint32
	for {
		var err error
		matchingPID, err = findSidProcess(sid)
		if err != nil {
			return fmt.Errorf("findSidProcess: %w", err)
		}

		if matchingPID != 0 {
			break
		}

		log.Printf("waiting for process  with SID %s to impersonate\n", sid)

		time.Sleep(1 * time.Second)
	}

	dupToken, err := duplicateProcessToken(matchingPID)
	if err != nil {
		return fmt.Errorf("duplicateProcessToken: %w", err)
	}
	defer dupToken.Close()

	if err := impersonateProcess(dupToken); err != nil {
		return fmt.Errorf("impersonateProcess: %w", err)
	}

	return nil
}

func findSidProcess(sid string) (uint32, error) {
	processIds := make([]uint32, 1000)
	var bytesReturned uint32
	if err := windows.EnumProcesses(processIds, &bytesReturned); err != nil {
		return 0, err
	}

	targetSID, err := windows.StringToSid(sid)
	if err != nil {
		return 0, fmt.Errorf("StringToSid %w", err)
	}

	var matchingPID uint32
	for _, pid := range processIds {
		if pid == 0 {
			continue
		}

		matches, err := processMatchesSid(pid, targetSID)
		if err != nil {
			return 0, fmt.Errorf("processMatchesSid %w", err)
		}
		if matches {
			matchingPID = pid
			break
		}
	}
	return matchingPID, nil
}

func impersonateProcess(dupToken windows.Token) error {
	currentHandle := windows.CurrentThread()
	defer windows.CloseHandle(currentHandle)

	if err := windows.SetThreadToken(&currentHandle, dupToken); err != nil {
		return fmt.Errorf("SetThreadToken: %w\n", err)
	}

	afterThreadToken := windows.GetCurrentThreadToken()
	defer afterThreadToken.Close()

	afterThreadUser, err := afterThreadToken.GetTokenUser()
	if err != nil {
		return fmt.Errorf("GetTokenUser: %w", err)
	}
	log.Printf("afterThreadUser SID: %s\n", afterThreadUser.User.Sid.String())

	return nil
}

func duplicateProcessToken(pid uint32) (windows.Token, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, fmt.Errorf("OpenProcess %d: %w\n", pid, err)
	}
	defer windows.CloseHandle(handle)

	var origToken windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE, &origToken); err != nil {
		return 0, fmt.Errorf("OpenProcessToken %d: %w\n", pid, err)
	}
	defer origToken.Close()

	var dupToken windows.Token
	if err := windows.DuplicateTokenEx(origToken, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &dupToken); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx %d: %w\n", pid, err)
	}
	return dupToken, nil
}

func processMatchesSid(pid uint32, targetSID *windows.SID) (bool, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		log.Printf("OpenProcess %d: %s\n", pid, err.Error())
		return false, nil
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		log.Printf("OpenProcessToken %d: %s\n", pid, err.Error())
		return false, nil

	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return false, err
	}

	return tokenUser.User.Sid.Equals(targetSID), nil
}
