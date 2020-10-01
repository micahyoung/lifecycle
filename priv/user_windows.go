package priv

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// EnsureOwner recursively chowns a dir if it isn't writable
func EnsureOwner(uid, gid int, paths ...string) error {
	ownerSID, err := windows.CreateWellKnownSid(windows.WELL_KNOWN_SID_TYPE(uid))
	if err != nil {
		return err
	}
	groupSID, err := windows.CreateWellKnownSid(windows.WELL_KNOWN_SID_TYPE(gid))
	if err != nil {
		return err
	}

	for _, p := range paths {
		_, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		sd, err := windows.GetNamedSecurityInfo(p,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION,
		)
		if err != nil {
			return err
		}

		if canWrite(ownerSID, groupSID, sd) {
			// if a dir has correct ownership, assume it's children do, for performance
			continue
		}

		if err := recursiveEnsureOwner(p, ownerSID, groupSID); err != nil {
			return err
		}
	}

	return nil
}

func canWrite(userSID, groupSID *windows.SID, sd *windows.SECURITY_DESCRIPTOR) bool {
	owner, _, err := sd.Owner()
	if err != nil {
		return false
	}
	fmt.Printf("OWNER: %s", owner)
	if owner.Equals(userSID) {
		return true
	}

	group, _, err := sd.Group()
	if err != nil {
		return false
	}
	fmt.Printf("GROUP: %s", group)
	if group.Equals(groupSID) {
		return true
	}

	//TODO check read only and writable
	return false
}

func recursiveEnsureOwner(path string, ownerSID, groupSID *windows.SID) error {
	acl, err := windows.ACLFromEntries(nil, nil)
	if err != nil {
		return err
	}

	if err := makeOwner(path, ownerSID, groupSID, acl); err != nil {
		return err
	}

	fis, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	for _, fi := range fis {
		filePath := filepath.Join(path, fi.Name())
		if fi.IsDir() {
			if err := recursiveEnsureOwner(filePath, ownerSID, groupSID); err != nil {
				return err
			}
		} else {
			if err := makeOwner(path, ownerSID, groupSID, acl); err != nil {
				return err
			}
		}
	}
	return nil
}

func makeOwner(path string, ownerSID, groupSID *windows.SID, acl *windows.ACL) error {
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, //todo deal with inheritance. see go-acl
		ownerSID,
		groupSID,
		acl,
		nil,
	)
}

//IsPrivileged returns true if user is member of local administrators
func IsPrivileged() bool {
	token := windows.GetCurrentProcessToken()

	userGroups, err := token.GetTokenGroups()
	if err != nil {
		// not fatal, unprivileged users may not be able to query token groups
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
