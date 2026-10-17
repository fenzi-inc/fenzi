package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"fenzi/cli/internal/openshell"
	"fenzi/cli/internal/tui"
)

// colimaRunner runs colima for the DNS check. Tests replace it.
var colimaRunner openshell.Runner = openshell.Exec{Bin: "colima"}

// onColima reports whether the gateway's sandboxes run in colima. Tests
// replace it, so a test never asks this machine's colima.
var onColima = func() bool { return openshell.Diagnose().OnColima() }

// restartColima stops colima's VM and starts it again. Tests replace it.
var restartColima = func(ctx context.Context) error {
	return openshell.StartRuntime(ctx, openshell.Runtime{
		Name:   "colima",
		Socket: openshell.ColimaSocket(),
		Start:  []string{"colima", "restart"},
	}, nil, nil, nil)
}

// colimaFile is colima's config file. Tests replace it.
var colimaFile = openshell.ColimaFile

// dnsSandboxes is how many running sandboxes the check tries before it
// gives up on asking from inside one.
const dnsSandboxes = 3

type dnsCheck struct {
	// where answered: "sandbox <name>", or "colima's resolver".
	where string
	host  string
	ttls  []uint32
	err   error
}

// checkDNS looks up an allowed name the way an agent does, from inside a
// running sandbox, so it works on any runtime and any cluster. With no
// sandbox running it asks colima's resolver on colima, and nothing elsewhere.
func checkDNS(e env, oc openshell.Client) dnsCheck {
	ctx, cancel := context.WithTimeout(e.ctx, time.Minute)
	defer cancel()
	why := errors.New("no sandbox is running to look a name up in")
	names, err := oc.Sandboxes(ctx)
	if err != nil {
		why = err
	}
	for i, sb := range names {
		if i == dnsSandboxes {
			break
		}
		policy, err := oc.EffectivePolicy(ctx, sb)
		if err != nil {
			continue
		}
		host := openshell.PolicyHost(policy)
		if host == "" {
			continue
		}
		ttls, err := oc.SandboxTTLs(ctx, sb, host)
		if err != nil {
			why = fmt.Errorf("sandbox %s: %w", sb, err)
			continue
		}
		return dnsCheck{where: "sandbox " + sb, host: host, ttls: ttls}
	}
	if onColima() {
		ttls, err := openshell.Colima{R: colimaRunner}.ResolverTTLs(ctx, openshell.DNSProbeName)
		return dnsCheck{where: "colima's resolver", host: openshell.DNSProbeName, ttls: ttls, err: err}
	}
	return dnsCheck{err: why}
}

func (c dnsCheck) short() bool { return c.err == nil && openshell.ShortTTL(c.ttls) }

// detail is what the check found, or why nothing was asked.
func (c dnsCheck) detail() string {
	switch {
	case c.err != nil && c.where != "":
		return "could not ask " + c.where + ": " + c.err.Error()
	case c.err != nil:
		return "not checked: " + c.err.Error()
	}
	return fmt.Sprintf("%s answers %s with a TTL of %d", c.where, c.host, slices.Min(c.ttls))
}

// shortTTL is what a TTL of 0 or 1 does, on any runtime.
const shortTTL = "The sandbox keeps each allowed name's address for that TTL, 1 second at least. An agent that connects after it expires is refused with transparent_tcp_mapping_denied, at random. The sandbox asks the runtime's resolver, and OpenShell has no setting for a longer time."

// otherRuntimes is the fix where Fenzi knows no setting to offer.
const otherRuntimes = "Point the runtime's DNS at a resolver that answers with real TTLs. What to change for each runtime: https://fenzi.dev/docs/troubleshooting#dns"

// setupDNS checks the TTL a sandbox sees. On colima it offers colima's dns
// setting when the TTL is too short, and changes nothing unless the person
// chooses it. On other runtimes it says what to change.
func setupDNS(e env, u *tui.UI, oc openshell.Client) error {
	c := checkDNS(e, oc)
	switch {
	case c.err != nil && c.where == "":
		u.Skip("DNS", "checked by fenzi doctor while a sandbox runs")
		return nil
	case c.err != nil:
		u.Skip("DNS", c.detail())
		return nil
	case !c.short():
		u.Done("DNS", c.detail())
		return nil
	}
	u.Problem("DNS", c.detail())
	u.Note(shortTTL)
	if !onColima() {
		u.Note(otherRuntimes)
		return nil
	}
	path := colimaFile()
	if err := openshell.CanSetColimaDNS(path); err != nil {
		u.Note("On colima: setup cannot change it, because " + err.Error() + ". Set dns in " + tilde(path, homeDir()) + " to resolvers that answer with real TTLs, then restart colima.")
		return nil
	}
	u.Note("On colima, setup can set this line in " + tilde(path, homeDir()) + ", then restart colima:")
	u.Blank()
	u.Println("      " + u.Dim(openshell.ColimaDNSLine(openshell.ColimaPublicDNS)))
	u.Blank()
	u.Note("Restarting colima stops every sandbox running in it, and their changes cannot be copied out afterwards; fenzi stop the ones you need first. A public resolver does not see your company's internal names. If agents need those, leave this and set dns to your company's resolvers yourself.")
	u.Blank()
	ok, err := u.Confirm("Set dns and restart colima?", "Yes, set it and restart colima", "No, leave colima as it is")
	if err != nil {
		return err
	}
	if !ok {
		u.Skip("DNS", "unchanged; agents may be refused at random")
		return nil
	}
	if err := openshell.SetColimaDNS(path, openshell.ColimaPublicDNS); err != nil {
		u.Problem("DNS", err.Error())
		return nil
	}
	u.Done("colima", "dns set in "+tilde(path, homeDir()))
	if _, err := u.Spin("colima", "restarting, this can take a minute", func() (string, error) {
		return "restarted", restartColima(e.ctx)
	}); err != nil {
		u.Note("Start colima again, then run fenzi setup.")
		return quietExit(3)
	}
	if oc.Ready(e.ctx) != nil && openshell.Service("restart") != nil {
		if _, err := u.Spin("Gateway", "restarting the service", func() (string, error) {
			return "service restarted", openshell.RunService(e.ctx, "restart")
		}); err != nil {
			return quietExit(3)
		}
	}
	if !waitGateway(e, u, oc) {
		return quietExit(3)
	}
	switch c = checkDNS(e, oc); {
	case c.err != nil:
		u.Skip("DNS", c.detail())
	case c.short():
		u.Problem("DNS", "still short: "+c.detail())
	default:
		u.Done("DNS", c.detail())
	}
	return nil
}

// doctorDNS is doctor's DNS line. It never changes the runtime.
func doctorDNS(e env, oc openshell.Client, line func(status, check, detail string)) {
	c := checkDNS(e, oc)
	switch {
	case c.err != nil:
		line("skip", "DNS", c.detail())
	case !c.short():
		line("ok", "DNS", c.detail())
	case !onColima():
		line("FAIL", "DNS", c.detail()+". "+shortTTL+" "+otherRuntimes)
	default:
		fix := "On colima, fenzi setup can set dns in " + tilde(colimaFile(), homeDir()) + "."
		if err := openshell.CanSetColimaDNS(colimaFile()); err != nil {
			fix = "On colima: " + strings.TrimSuffix(err.Error(), ".") + "; set it to resolvers that answer with real TTLs, then restart colima."
		}
		line("FAIL", "DNS", c.detail()+". "+shortTTL+" "+fix)
	}
}
