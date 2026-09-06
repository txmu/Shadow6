//go:build windows

package main

import (
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func readSecretFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("secret file must be regular, bounded, and ACL-protected")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() {
		return nil, errors.New("secret file security descriptor unavailable")
	}
	owner, _, err := sd.Owner()
	token, tokenErr := windows.OpenCurrentProcessToken()
	if err != nil || tokenErr != nil {
		return nil, errors.New("secret file owner unavailable")
	}
	defer token.Close()
	user, userErr := token.GetTokenUser()
	if owner == nil || userErr != nil || !windows.EqualSid(owner, user.User.Sid) {
		return nil, errors.New("secret file is not owned by the current user")
	}
	sddl := sd.String()
	for _, principal := range []string{";WD)", ";AU)", ";BU)", ";BG)", ";AN)"} {
		if strings.Contains(sddl, principal) {
			return nil, errors.New("secret file ACL grants access to a broad principal")
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() > maximum {
		return nil, errors.New("secret file changed during validation")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("secret file exceeds size limit")
	}
	return data, nil
}
