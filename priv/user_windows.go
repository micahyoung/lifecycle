package priv

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// EnsureOwner recursively chowns a dir if it isn't writable
func EnsureOwner(uid, gid int, paths ...string) error {
	for _, p := range paths {
		_, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err := recursiveEnsureOwner(p, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func recursiveEnsureOwner(path string, uid, gid int) error {
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	fis, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	for _, fi := range fis {
		filePath := filepath.Join(path, fi.Name())
		if fi.IsDir() {
			if err := recursiveEnsureOwner(filePath, uid, gid); err != nil {
				return err
			}
		} else {
			if err := os.Lchown(filePath, uid, gid); err != nil {
				return err
			}
		}
	}
	return nil
}

//IsPrivileged returns true if user is member of local administrators
func IsPrivileged() bool {
	token := windows.GetCurrentProcessToken()

	userGroups, err := token.GetTokenGroups()
	if err != nil {
		// non-fatal, unprivileged users may not be able to query token groups
		return false
	}

	for _, group := range userGroups.AllGroups() {
		if group.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return true
		}
	}

	return false
}

func RunAs(uid, gid int) error {
	return nil
}

func SetEnvironmentForUser(uid int) error {
	return nil
}
