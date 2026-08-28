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
		releaseAppPort(23177)
		got, err := checkPort("PANEL_APP_PORT_HTTP", params)
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
		if _, err := checkPort("PANEL_APP_PORT_HTTP", params); err == nil {
			t.Fatal("second checkPort of the same port succeeded, want ErrPortInUsed")
		} else if !isPortErr(err) {
			t.Fatalf("second checkPort error = %v, want ErrPortInUsed", err)
		}
	})

	t.Run("release frees the port for a later install", func(t *testing.T) {
		releaseAppPort(23177)
		got, err := checkPort("PANEL_APP_PORT_HTTP", params)
		if err != nil {
			t.Fatalf("checkPort after release failed: %v", err)
		}
		if got != 23177 {
			t.Fatalf("checkPort after release returned port %d, want 23177", got)
		}
		releaseAppPort(23177)
	})

	t.Run("release is idempotent and unregistering an unknown port is safe", func(t *testing.T) {
		releaseAppPort(23177)
		releaseAppPort(23178)
		releaseAppPort(23177)
	})

	t.Run("concurrent claims allow exactly one winner", func(t *testing.T) {
		releaseAppPort(23179)
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
				if _, err := checkPort("PANEL_APP_PORT_HTTP", params); err == nil {
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
		releaseAppPort(23179)
	})
}
