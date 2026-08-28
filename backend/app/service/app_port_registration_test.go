package service

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
)

// TestCheckPortRegistration is the regression test for the P2-3 race: checkPort
// is a check-then-act, so a port validated by a first install must be claimed
// in-process until the install either persists it in the DB or fails. A second
// checkPort of the same port (a concurrent install) must fail, and the port
// must be usable again after the claim is released (install failed or app
// deleted).
func TestCheckPortRegistration(t *testing.T) {
	setupAppInstallResultTest(t)

	const port = "23177"
	params := map[string]interface{}{"PANEL_APP_PORT_HTTP": port}

	// the test asserts on the buserr key, so the i18n message lookup of
	// Error() must never run
	isPortErr := func(err error) bool {
		if err == nil {
			return false
		}
		var be buserr.BusinessError
		return errors.As(err, &be) && be.Msg == constant.ErrPortInUsed
	}

	t.Run("second check of a registered port is rejected", func(t *testing.T) {
		forceReleaseAppPort(23177)
		got, _, err := checkPort("PANEL_APP_PORT_HTTP", params)
		if err != nil {
			t.Fatalf("first checkPort failed: %v", err)
		}
		if got != 23177 {
			t.Fatalf("first checkPort returned port %d, want 23177", got)
		}
		if _, loaded := registeredPorts.Load(23177); !loaded {
			t.Fatal("first checkPort did not register the port")
		}

		// a concurrent install of the same port must be rejected without the
		// port having to be bound on the host
		if _, _, err := checkPort("PANEL_APP_PORT_HTTP", params); err == nil {
			t.Fatal("second checkPort of the same port succeeded, want ErrPortInUsed")
		} else if !isPortErr(err) {
			t.Fatalf("second checkPort error = %v, want ErrPortInUsed", err)
		}
		forceReleaseAppPort(23177)
	})

	t.Run("release with the checkPort token frees the port for a later install", func(t *testing.T) {
		forceReleaseAppPort(23177)
		got, token, err := checkPort("PANEL_APP_PORT_HTTP", params)
		if err != nil {
			t.Fatalf("checkPort after release failed: %v", err)
		}
		if got != 23177 {
			t.Fatalf("checkPort after release returned port %d, want 23177", got)
		}
		releaseAppPort(got, token)
		if _, loaded := registeredPorts.Load(23177); loaded {
			t.Fatal("release with the owner token did not drop the claim")
		}
		got, _, err = checkPort("PANEL_APP_PORT_HTTP", params)
		if err != nil {
			t.Fatalf("checkPort after owner release failed: %v", err)
		}
		forceReleaseAppPort(got)
	})

	t.Run("release is idempotent and unregistering an unknown port is safe", func(t *testing.T) {
		forceReleaseAppPort(23177)
		// a second release with the same token, and releases of ports that
		// were never registered, must all be no-ops
		releaseAppPort(23177, 1)
		releaseAppPort(23177, 1)
		releaseAppPort(23178, 42)
		forceReleaseAppPort(23178)
	})

	t.Run("concurrent claims allow exactly one winner", func(t *testing.T) {
		forceReleaseAppPort(23179)
		const workers = 32
		var (
			wg       sync.WaitGroup
			winners  int32
			mu       sync.Mutex
			winnersN int
		)
		params := map[string]interface{}{"PANEL_APP_PORT_HTTP": "23179"}
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, _, err := checkPort("PANEL_APP_PORT_HTTP", params); err == nil {
					mu.Lock()
					winnersN++
					mu.Unlock()
					// keep the claim: a passing check must be accompanied by
					// a registration
					atomic.AddInt32(&winners, 1)
				}
			}()
		}
		wg.Wait()
		mu.Lock()
		got := winnersN
		mu.Unlock()
		if got != 1 {
			t.Fatalf("%d goroutines passed checkPort for the same port, want exactly 1", got)
		}
		if atomic.LoadInt32(&winners) != 1 {
			t.Fatalf("registered count = %d, want 1", atomic.LoadInt32(&winners))
		}
		forceReleaseAppPort(23179)
	})
}

// TestAppPortClaimOwnership is the regression test for the ownership gap: a
// claim used to be a bare struct{} that any releaseAppPort call could delete,
// so flow B mistakenly releasing a port that flow A had claimed (e.g. a
// failed-install cleanup racing A's own cleanup) silently dropped A's
// protection and re-opened the double-install race. A release must only drop
// the claim whose token it holds.
func TestAppPortClaimOwnership(t *testing.T) {
	t.Run("a foreign token cannot drop another flow's claim", func(t *testing.T) {
		forceReleaseAppPort(23180)
		token, ok := tryRegisterAppPort(23180)
		if !ok {
			t.Fatal("tryRegisterAppPort failed on a free port")
		}
		// a second claim of the same port must still be rejected
		if _, ok := tryRegisterAppPort(23180); ok {
			t.Fatal("second tryRegisterAppPort of the same port succeeded")
		}
		// flow B holds a different token (tokens are unique, so token+1
		// simulates any foreign/stale token): releasing with it must not
		// drop flow A's claim
		releaseAppPort(23180, token+1)
		if _, loaded := registeredPorts.Load(23180); !loaded {
			t.Fatal("foreign-token release dropped the live claim")
		}
		// the real owner can still free the port
		releaseAppPort(23180, token)
		if _, loaded := registeredPorts.Load(23180); loaded {
			t.Fatal("owner-token release did not drop the claim")
		}
	})

	t.Run("stale token cannot release a re-claimed port", func(t *testing.T) {
		forceReleaseAppPort(23181)
		first, ok := tryRegisterAppPort(23181)
		if !ok {
			t.Fatal("first claim failed")
		}
		releaseAppPort(23181, first)
		// a later flow re-claims the same port with a fresh token; the first
		// flow's stale token must be powerless against it
		second, ok := tryRegisterAppPort(23181)
		if !ok {
			t.Fatal("re-claim after release failed")
		}
		if second == first {
			t.Fatal("claim tokens are not unique")
		}
		releaseAppPort(23181, first)
		if _, loaded := registeredPorts.Load(23181); !loaded {
			t.Fatal("stale token dropped the new claim")
		}
		releaseAppPort(23181, second)
	})

	t.Run("forceReleaseAppPort drops any claim (end-of-life cleanup)", func(t *testing.T) {
		forceReleaseAppPort(23182)
		token, ok := tryRegisterAppPort(23182)
		if !ok {
			t.Fatal("claim failed")
		}
		forceReleaseAppPort(23182)
		if _, loaded := registeredPorts.Load(23182); loaded {
			t.Fatal("forceReleaseAppPort did not drop the claim")
		}
		// the stale token release afterwards must stay a no-op
		releaseAppPort(23182, token)
	})
}

// TestResetAppPortClaims is the regression test for stale port claims after a
// snapshot recover/rollback: those flows replace the whole app_installs table
// with the snapshot's rows and restart the panel into the recovered database,
// so no in-flight claim may survive the restore — a surviving claim would make
// the panel falsely reject new installs on the recovered apps' ports until the
// restart.
func TestResetAppPortClaims(t *testing.T) {
	const (
		portA = 23183
		portB = 23184
	)
	for _, port := range []int{portA, portB} {
		forceReleaseAppPort(port)
		defer forceReleaseAppPort(port)
	}

	// precondition: two live claims like installs in flight when a recover
	// replaces app_installs
	for _, port := range []int{portA, portB} {
		if _, ok := tryRegisterAppPort(port); !ok {
			t.Fatalf("claim of port %d failed", port)
		}
	}
	if _, loaded := registeredPorts.Load(portA); !loaded {
		t.Fatal("precondition failed: portA claim missing")
	}

	resetAppPortClaims()

	for _, port := range []int{portA, portB} {
		if _, loaded := registeredPorts.Load(port); loaded {
			t.Fatalf("port %d claim survived resetAppPortClaims", port)
		}
	}
	// the table must stay fully usable afterwards: a fresh claim of a port
	// won immediately, and releasing it with its own token works
	token, ok := tryRegisterAppPort(portA)
	if !ok {
		t.Fatal("claim after reset failed")
	}
	releaseAppPort(portA, token)
	if _, loaded := registeredPorts.Load(portA); loaded {
		t.Fatal("release after reset did not drop the fresh claim")
	}
}
