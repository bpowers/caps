// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !cgo

package caps

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/user"
	"strings"
)

const (
	fieldUsername = iota
	fieldPassword
	fieldUid
	fieldGid
	fieldGecos
	fieldHomeDir
	fieldShell
)

// EtcPasswdLookup looks up a user by username. If the user cannot be
// found, the returned error is of type user.UnknownUserError.  This
// differs from os/user.Lookup by parsing /etc/password directly, so
// it doesn't need cgo support.
func EtcPasswdLookup(username string) (*user.User, error) {
	usernamePrefix := []byte(username)
	usernamePrefix = append(usernamePrefix, ':')
	etcPasswd, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}

	passwdReader := bufio.NewReader(bytes.NewReader(etcPasswd))
	for {
		l, isPrefix, err := passwdReader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if isPrefix {
			return nil, fmt.Errorf("passwd: line too long: '%s'", l)
		}
		if !bytes.HasPrefix(l, usernamePrefix) {
			continue
		}
		fields := strings.Split(string(l), ":")
		if len(fields) != 7 {
			log.Printf("/etc/passwd: wrong num fields (%d): %s\n",
				len(fields), string(l))
			continue
		}

		// The pw_gecos field isn't standardized.  Some docs
		// say: "It is expected to be a comma separated list
		// of personal data where the first item is the full
		// name of the user."
		fullName := strings.SplitN(fields[fieldGecos], ",", 2)[0]

		return &user.User{
			Uid:      fields[fieldUid],
			Gid:      fields[fieldGid],
			Username: fields[fieldUsername],
			Name:     fullName,
			HomeDir:  fields[fieldHomeDir],
		}, nil
	}

	return nil, user.UnknownUserError(username)
}

// os/user.Lookup depends on cgo.  When cgo is disabled (for static
// linking purposes), caps falls back to parsing /etc/passwd directly.
// Override this behavior as desired.
var Lookup = EtcPasswdLookup
