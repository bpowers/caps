// Copyright 2012 Bobby Powers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo

package caps

import (
	"os/user"
)

// os/user.Lookup depends on cgo.  When cgo is disabled (for static
// linking purposes), caps falls back to parsing /etc/passwd directly.
// Override this behavior as desired.
var Lookup = user.Lookup
