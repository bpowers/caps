// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin freebsd linux netbsd

package caps

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// Current returns the current user. 
func Current() (*user.User, error) {
	return lookup(syscall.Getuid(), "", false)
}

// Lookup looks up a user by username. If the user cannot be found,
// the returned error is of type UnknownUserError.
func Lookup(username string) (*user.User, error) {
	return lookup(-1, username, true)
}

// LookupId looks up a user by userid. If the user cannot be found,
// the returned error is of type UnknownUserIdError.
func LookupId(uid string) (*user.User, error) {
	i, e := strconv.Atoi(uid)
	if e != nil {
		return nil, e
	}
	return lookup(i, "", false)
}

const (
	fieldUsername = iota
	fieldPassword
	fieldUid
	fieldGid
	fieldGecos
	fieldHomeDir
	fieldShell
)

func lookup(uid int, username string, lookupByName bool) (*user.User, error) {
	usernamePrefix := []byte(username)
	usernamePrefix = append(usernamePrefix, ':')
	etcPasswd, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}

	var u *user.User

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
		if lookupByName {
			if !bytes.HasPrefix(l, usernamePrefix) {
				continue
			}
			fields := strings.Split(string(l), ":")
			if len(fields) != 7 {
				return nil, fmt.Errorf("passwd: wrong num fields: %d", len(fields))
			}
			u = &user.User{
				Uid: fields[fieldUid],
				Gid: fields[fieldGid],
				Username: fields[fieldUsername],
				Name: fields[fieldGecos],
				HomeDir: fields[fieldHomeDir],
			}
			break
		} else {
			// TODO: implement...
		}
	}

	if u == nil {
		return nil, fmt.Errorf("unknown user '%s'", username)
	}

	// The pw_gecos field isn't quite standardized.  Some docs
	// say: "It is expected to be a comma separated list of
	// personal data where the first item is the full name of the
	// user."
	if i := strings.Index(u.Name, ","); i >= 0 {
		u.Name = u.Name[:i]
	}
	return u, nil
}
