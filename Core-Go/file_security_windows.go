//go:build windows

package main

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// Windows permission bits are only a coarse compatibility projection. Use the
// native security descriptor and require the current token SID as owner.
func secureConfigFile(info os.FileInfo) bool { return info.Mode().IsRegular() }

func secureConfigPath(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || owner == nil || !windows.EqualSid(owner, user.User.Sid) {
		return false
	}
	// Reject broad principals in the canonical SDDL (Everyone, Authenticated
	// Users, Users, Guests, and Anonymous). SYSTEM/admin inheritance is allowed.
	sddl := sd.String()
	for _, principal := range []string{";WD)", ";AU)", ";BU)", ";BG)", ";AN)"} {
		if strings.Contains(sddl, principal) {
			return false
		}
	}
	return true
}
