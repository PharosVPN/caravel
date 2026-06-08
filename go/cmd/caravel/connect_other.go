// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

//go:build !linux

package main

import "errors"

// cmdConnect is Linux-only (tun device + iproute2). On other platforms the
// headless client still enrolls/syncs/lists; bring the tunnel up on Linux.
func cmdConnect(_ []string) error {
	return errors.New("connect is only supported on Linux (tun + iproute2); enroll/sync/list work everywhere")
}
