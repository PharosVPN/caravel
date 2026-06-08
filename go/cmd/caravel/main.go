// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Command caravel is the headless reference client for the caravel core. It runs
// on a plain Linux box (no GUI) and exercises the whole device lifecycle:
//
//	caravel enroll '<pharosvpn://enroll?...>' [--name NAME] [--platform P]
//	    Redeem a join-link/QR: generate keys on-device, claim the one-time
//	    ticket (cert-less, no account passphrase), assemble the `.pharosid`,
//	    sync the per-device-sealed profile, and store it — all in one step.
//	caravel sync <file.pharosid> [--email E] [--password PW] [--name NAME]
//	    Legacy account-sync from an imported `.pharosid`.
//	caravel list [--json]                       list stored profiles
//	caravel inspect <name>                      show a stored profile's nodes
//	caravel connect <name> [--node ID] [--no-default-route]
//	    Bring up the AmneziaWG tunnel on a tun device (needs root).
//	caravel rm <name>                           forget a profile
//
// It is a thin shell over the core: enroll/sync/list reuse core.Enroll,
// core.SyncAndStore, and the profile store unchanged; connect creates the tun
// device + iproute2 routes here (the only host-specific part).
//
// The store lives at $CARAVEL_HOME (default /etc/pharos/profiles), 0600 blobs.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/PharosVPN/caravel/core"
	"github.com/PharosVPN/caravel/core/deviceid"
	"github.com/PharosVPN/caravel/core/enroll"
	"github.com/PharosVPN/caravel/core/profile"
)

// version is stamped at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "caravel:", err)
		os.Exit(1)
	}
}

// storeDir is the on-disk profile store; overridable for testing/non-root runs.
func storeDir() string {
	if d := os.Getenv("CARAVEL_HOME"); d != "" {
		return d
	}
	return "/etc/pharos/profiles"
}

func dispatch(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("a subcommand is required")
	}
	switch args[0] {
	case "enroll":
		return cmdEnroll(args[1:])
	case "sync":
		return cmdSync(args[1:])
	case "list", "ls":
		return cmdList(args[1:])
	case "inspect":
		return cmdInspect(args[1:])
	case "connect", "up":
		return cmdConnect(args[1:])
	case "rm", "remove":
		return cmdRemove(args[1:])
	case "version", "-v", "--version":
		fmt.Println("caravel", version)
		return nil
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `caravel — headless PharosVPN client

  caravel enroll '<pharosvpn://enroll?...>' [--name NAME] [--platform P]
                                       redeem a join link (keygen + claim + sync), no passphrase
  caravel sync <file.pharosid> [--email E] [--password PW] [--name NAME]
                                       legacy account-sync from a .pharosid
  caravel list [--json]                list stored profiles
  caravel inspect <name>               show a stored profile's connections/nodes
  caravel connect <name> [--node ID] [--no-default-route]
                                       bring up the tunnel (needs root)
  caravel rm <name>                    forget a profile

  store: $CARAVEL_HOME (default /etc/pharos/profiles)
`)
}

// initStore points the core at the profile store.
func initStore() error { return core.InitStore(storeDir()) }

// cmdEnroll redeems a `pharosvpn://enroll` join link end-to-end: it generates the
// device's keys on-device, claims the one-time ticket through the relay (no
// account passphrase), assembles the `.pharosid`, syncs the per-device-sealed
// profile, and stores it ready to connect.
func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	name := fs.String("name", "", "device name recorded on the controller (and the local profile name)")
	platform := fs.String("platform", "caravel", "device platform/kind")
	if err := fs.Parse(args); err != nil {
		return err
	}
	link := fs.Arg(0)
	if link == "" {
		return errors.New("usage: caravel enroll '<pharosvpn://enroll?...>' [--name NAME] [--platform P]")
	}
	// Validate the link shape up front for a clearer error than a dial failure.
	if _, err := enroll.ParseLink(link); err != nil {
		return err
	}
	if err := initStore(); err != nil {
		return err
	}
	stored, err := core.Enroll(link, *name, *platform)
	if err != nil {
		return err
	}
	fmt.Printf("enrolled + synced profile %q in %s\n", stored, storeDir())
	fmt.Printf("connect with:  sudo caravel connect %s\n", stored)
	return nil
}

// cmdSync runs the legacy account-sync path from an imported `.pharosid`.
func cmdSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	email := fs.String("email", "", "account email (opts into passphrase login; omit for cert-auth)")
	password := fs.String("password", "", "account passphrase (or --password-stdin)")
	pwStdin := fs.Bool("password-stdin", false, "read the passphrase from stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	src := fs.Arg(0)
	if src == "" {
		return errors.New("usage: caravel sync <file.pharosid> [--email E] [--password PW]")
	}
	pid, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if _, err := deviceid.Parse(pid); err != nil {
		return err
	}
	pw := *password
	if *pwStdin {
		b, rerr := io.ReadAll(os.Stdin)
		if rerr != nil {
			return fmt.Errorf("read passphrase from stdin: %w", rerr)
		}
		pw = strings.TrimRight(string(b), "\r\n")
	}
	if err := initStore(); err != nil {
		return err
	}
	stored, err := core.SyncAndStore(pid, *email, pw)
	if err != nil {
		return err
	}
	fmt.Printf("synced profile %q in %s\n", stored, storeDir())
	return nil
}

// cmdList lists stored profiles via the core (its flattened JSON view).
func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := initStore(); err != nil {
		return err
	}
	if *jsonOut {
		fmt.Println(core.ListProfiles())
		return nil
	}
	st, err := profile.NewStore(storeDir())
	if err != nil {
		return err
	}
	entries, err := st.List()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Printf("no profiles in %s — enroll one with `caravel enroll '<link>'`\n", storeDir())
		return nil
	}
	fmt.Printf("profiles in %s:\n", storeDir())
	for _, e := range entries {
		fmt.Printf("  %-24s (%s)\n", e.Name, e.Enc)
	}
	return nil
}

// cmdInspect prints the stored profile's connections/nodes.
func cmdInspect(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: caravel inspect <name>")
	}
	if err := initStore(); err != nil {
		return err
	}
	st, err := profile.NewStore(storeDir())
	if err != nil {
		return err
	}
	data, err := st.Raw(args[0])
	if err != nil {
		return err
	}
	p, err := profile.Parse(data, profile.Options{})
	if err != nil {
		return err
	}
	fmt.Printf("profile %q (fleet %s)\n", args[0], p.FleetID)
	for i := range p.Profiles {
		cp := &p.Profiles[i]
		fmt.Printf("  · %s [%s]\n", cp.Name, cp.Protocol)
		for _, n := range cp.Nodes {
			fmt.Printf("      - %s (%s) %s\n", n.Name, n.Region, strings.Join(n.Endpoints, ","))
		}
	}
	return nil
}

// cmdRemove forgets a stored profile (and its sidecars).
func cmdRemove(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: caravel rm <name>")
	}
	st, err := profile.NewStore(storeDir())
	if err != nil {
		return err
	}
	for _, suf := range []string{profile.Extension, ".synced", deviceid.Extension} {
		_ = os.Remove(filepath.Join(st.Dir(), args[0]+suf))
	}
	fmt.Printf("removed profile %q\n", args[0])
	return nil
}
