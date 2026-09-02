package service

import (
	"fmt"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// setupUpgradeStatusTest prepares an in-memory DB with the Setting table and
// seeds SystemStatus=Free, mirroring setupRecoverStatusTest.
func setupUpgradeStatusTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate setting table failed: %v", err)
	}
	oldDB, oldLog := global.DB, global.LOG
	global.DB = db
	global.LOG = logrus.New()
	t.Cleanup(func() { global.DB, global.LOG = oldDB, oldLog })
	if err := settingRepo.Create("SystemStatus", "Free"); err != nil {
		t.Fatalf("seed SystemStatus=Free failed: %v", err)
	}
}

// assertUpgradeBusy asserts err is the ErrUpgradeTaskBusy business error.
func assertUpgradeBusy(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected business error %s, got nil", constant.ErrUpgradeTaskBusy)
	}
	be, ok := err.(buserr.BusinessError)
	if !ok || be.Msg != constant.ErrUpgradeTaskBusy {
		t.Fatalf("expected business error %s, got %v", constant.ErrUpgradeTaskBusy, err)
	}
}

// TestClaimUpgradeStatusSingleWinner verifies the upgrade claim semantics:
// the first claim flips SystemStatus Free -> Upgrading, a second claim is
// refused while it is Upgrading (the concurrent-upgrade guard), and after
// the status is reset to Free the claim succeeds again.
func TestClaimUpgradeStatusSingleWinner(t *testing.T) {
	setupUpgradeStatusTest(t)
	u := &UpgradeService{}
	if err := u.claimUpgradeStatus(); err != nil {
		t.Fatalf("first claim should succeed: %v", err)
	}
	var s model.Setting
	if err := global.DB.Where("key = ?", "SystemStatus").First(&s).Error; err != nil {
		t.Fatal(err)
	}
	if s.Value != "Upgrading" {
		t.Fatalf("SystemStatus = %q after claim, want Upgrading", s.Value)
	}
	// A second upgrade while the first is in flight must be refused.
	assertUpgradeBusy(t, u.claimUpgradeStatus())
	// The goroutine resets the status when the upgrade finishes.
	if err := settingRepo.Update("SystemStatus", "Free"); err != nil {
		t.Fatal(err)
	}
	if err := u.claimUpgradeStatus(); err != nil {
		t.Fatalf("claim after reset should succeed: %v", err)
	}
}

// TestClaimUpgradeStatusRefusedWhenBusy verifies that an upgrade is refused
// while any other exclusive flow owns SystemStatus (e.g. a snapshot recover
// left it Recovering), so the upgrade can never overwrite binaries during a
// recover/rollback.
func TestClaimUpgradeStatusRefusedWhenBusy(t *testing.T) {
	setupUpgradeStatusTest(t)
	u := &UpgradeService{}
	for _, busyStatus := range []string{"Recovering"} {
		if err := settingRepo.Update("SystemStatus", busyStatus); err != nil {
			t.Fatal(err)
		}
		assertUpgradeBusy(t, u.claimUpgradeStatus())
		var s model.Setting
		if err := global.DB.Where("key = ?", "SystemStatus").First(&s).Error; err != nil {
			t.Fatal(err)
		}
		if s.Value != busyStatus {
			t.Fatalf("failed claim must not modify SystemStatus: got %q want %q", s.Value, busyStatus)
		}
	}
}

// TestSettingRepoCAS pins the atomic CAS primitive: it flips the row exactly
// once for the winner and never for a second caller, also when the value no
// longer matches.
func TestSettingRepoCAS(t *testing.T) {
	setupUpgradeStatusTest(t)
	ok, err := settingRepo.CAS("SystemStatus", "Free", "Upgrading")
	if err != nil || !ok {
		t.Fatalf("first CAS should win: ok=%v err=%v", ok, err)
	}
	ok, err = settingRepo.CAS("SystemStatus", "Free", "Upgrading")
	if err != nil || ok {
		t.Fatalf("second CAS with stale expect should lose: ok=%v err=%v", ok, err)
	}
	ok, err = settingRepo.CAS("SystemStatus", "Upgrading", "Free")
	if err != nil || !ok {
		t.Fatalf("CAS back to Free should win: ok=%v err=%v", ok, err)
	}
}
