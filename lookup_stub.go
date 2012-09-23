// Copyright 2012 Bobby Powers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows
// +build cgo

package caps

import (
	"os/user"
)

func EtcPasswdLookup(username string) (*user.User, error) {
	return user.Lookup(username)
}
