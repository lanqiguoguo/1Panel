package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/firewall"
	fireClient "github.com/1Panel-dev/1Panel/backend/utils/firewall/client"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// The update/batch decision logic is exercised through the
// newFirewallClientFn seam (default: firewall.NewFirewallClient) against a
// scripted in-memory client, since the unit-test host has no firewalld/ufw.

// --- pure decision logic ------------------------------------------------

func TestOldPortRuleIsNoopRemove(t *testing.T) {
	cases := []struct {
		name string
		old  dto.PortRuleOperate
		want bool
	}{
		{"empty remove is a noop", dto.PortRuleOperate{Operation: "remove"}, true},
		{"Anywhere remove is a noop", dto.PortRuleOperate{Operation: "remove", Address: "Anywhere"}, true},
		{"noop with tcp/udp protocol", dto.PortRuleOperate{Operation: "remove", Protocol: "tcp/udp"}, true},
		{"real remove has a port", dto.PortRuleOperate{Operation: "remove", Port: "22", Protocol: "tcp", Strategy: "accept"}, false},
		{"add is never a noop", dto.PortRuleOperate{Operation: "add", Port: "80", Protocol: "tcp", Strategy: "accept"}, false},
		{"remove with only strategy is not noop", dto.PortRuleOperate{Operation: "remove", Strategy: "drop"}, false},
	}
	for _, tc := range cases {
		if got := oldPortRuleIsNoopRemove(tc.old); got != tc.want {
			t.Errorf("%s: oldPortRuleIsNoopRemove(%+v) = %v, want %v", tc.name, tc.old, got, tc.want)
		}
	}
}

func TestAddrRuleIsNoopRemove(t *testing.T) {
	cases := []struct {
		name string
		old  dto.AddrRuleOperate
		want bool
	}{
		{"empty remove is a noop", dto.AddrRuleOperate{Operation: "remove"}, true},
		{"real remove has an address", dto.AddrRuleOperate{Operation: "remove", Address: "1.2.3.4", Strategy: "drop"}, false},
		{"add is never a noop", dto.AddrRuleOperate{Operation: "add", Address: "1.2.3.4", Strategy: "accept"}, false},
	}
	for _, tc := range cases {
		if got := addrRuleIsNoopRemove(tc.old); got != tc.want {
			t.Errorf("%s: addrRuleIsNoopRemove(%+v) = %v, want %v", tc.name, tc.old, got, tc.want)
		}
	}
}

// The plain-vs-rich classifier (oldRuleIsPortOperation) was dropped during
// the fix: UpdatePortRule deletes the old rule first and rolls it back on a
// failed add for every rule shape (see TestUpdatePortRule* below).

func TestPortRulesMatch(t *testing.T) {
	accept22 := dto.PortRuleOperate{Port: "22", Protocol: "tcp", Strategy: "accept"}
	cases := []struct {
		name string
		item fireClient.FireInfo
		r    dto.PortRuleOperate
		want bool
	}{
		{"exact match", fireClient.FireInfo{Port: "22", Protocol: "tcp"}, accept22, true},
		{"firewalld direct port entries carry no strategy", fireClient.FireInfo{Port: "22", Protocol: "tcp", Strategy: "accept"}, accept22, true},
		{"item without protocol matches any protocol", fireClient.FireInfo{Port: "22"}, accept22, true},
		{"tcp/udp request matches a tcp rule", fireClient.FireInfo{Port: "22", Protocol: "tcp"}, dto.PortRuleOperate{Port: "22", Protocol: "tcp/udp", Strategy: "accept"}, true},
		{"tcp request does not match udp rule", fireClient.FireInfo{Port: "22", Protocol: "udp"}, accept22, false},
		{"different port", fireClient.FireInfo{Port: "23", Protocol: "tcp"}, accept22, false},
		{"different strategy", fireClient.FireInfo{Port: "22", Protocol: "tcp", Strategy: "drop"}, accept22, false},
		{"address query must see its own address", fireClient.FireInfo{Port: "22", Protocol: "tcp", Address: "1.2.3.4"}, dto.PortRuleOperate{Port: "22", Protocol: "tcp", Address: "5.6.7.8", Strategy: "accept"}, false},
		{"unaddressed query rejects addressed entries", fireClient.FireInfo{Port: "22", Protocol: "tcp", Address: "1.2.3.4"}, accept22, false},
		{"drop rich rule matches drop", fireClient.FireInfo{Port: "22", Protocol: "tcp", Address: "1.2.3.4", Strategy: "drop"}, dto.PortRuleOperate{Port: "22", Protocol: "tcp", Address: "1.2.3.4", Strategy: "drop"}, true},
	}
	for _, tc := range cases {
		if got := portRulesMatch(tc.item, tc.r); got != tc.want {
			t.Errorf("%s: portRulesMatch(%+v, %+v) = %v, want %v", tc.name, tc.item, tc.r, got, tc.want)
		}
	}
}

func TestAddrRulesMatch(t *testing.T) {
	cases := []struct {
		name string
		item fireClient.FireInfo
		r    dto.AddrRuleOperate
		want bool
	}{
		{"address-only drop rule", fireClient.FireInfo{Address: "1.2.3.4", Strategy: "drop"}, dto.AddrRuleOperate{Address: "1.2.3.4", Strategy: "drop"}, true},
		{"accept strategy matches empty strategy entry", fireClient.FireInfo{Address: "1.2.3.4"}, dto.AddrRuleOperate{Address: "1.2.3.4", Strategy: "accept"}, true},
		{"different address", fireClient.FireInfo{Address: "1.2.3.5", Strategy: "drop"}, dto.AddrRuleOperate{Address: "1.2.3.4", Strategy: "drop"}, false},
		{"strategy mismatch", fireClient.FireInfo{Address: "1.2.3.4", Strategy: "accept"}, dto.AddrRuleOperate{Address: "1.2.3.4", Strategy: "drop"}, false},
		{"port-carrying entries are not address rules", fireClient.FireInfo{Address: "1.2.3.4", Strategy: "drop", Port: "22"}, dto.AddrRuleOperate{Address: "1.2.3.4", Strategy: "drop"}, false},
	}
	for _, tc := range cases {
		if got := addrRulesMatch(tc.item, tc.r); got != tc.want {
			t.Errorf("%s: addrRulesMatch(%+v, %+v) = %v, want %v", tc.name, tc.item, tc.r, got, tc.want)
		}
	}
}

// --- mocked end-to-end update semantics --------------------------------

// seqFirewallClient records the order of firewall operations and can fail the
// nth one (1-based). ListPort/ListAddress return the current rules so the
// update rollback helpers can check whether a rule is already in effect.
type seqFirewallClient struct {
	name        string
	seq         []string
	failAt      int // 0 = never fail
	directPorts map[string]bool
	richRules   []fireClient.FireInfo
}

func (c *seqFirewallClient) Name() string { return c.name }
func (c *seqFirewallClient) Start() error { return nil }
func (c *seqFirewallClient) Stop() error  { return nil }
func (c *seqFirewallClient) Restart() error {
	return c.step("restart")
}
func (c *seqFirewallClient) Reload() error {
	return c.step("reload")
}
func (c *seqFirewallClient) Status() (string, error) { return "running", nil }
func (c *seqFirewallClient) Version() (string, error) {
	return "test", nil
}
func (c *seqFirewallClient) ListPort() ([]fireClient.FireInfo, error) {
	var out []fireClient.FireInfo
	for k := range c.directPorts {
		parts := strings.Split(k, "/")
		out = append(out, fireClient.FireInfo{Port: parts[0], Protocol: parts[1]})
	}
	return out, nil
}
func (c *seqFirewallClient) ListForward() ([]fireClient.FireInfo, error) {
	return nil, nil
}
func (c *seqFirewallClient) ListAddress() ([]fireClient.FireInfo, error) {
	return c.richRules, nil
}
func (c *seqFirewallClient) Port(info fireClient.FireInfo, operation string) error {
	if err := c.step("port " + operation + " " + info.Port + "/" + info.Protocol); err != nil {
		return err
	}
	if operation == "add" {
		c.directPorts[info.Port+"/"+info.Protocol] = true
	} else {
		delete(c.directPorts, info.Port+"/"+info.Protocol)
	}
	return nil
}
func (c *seqFirewallClient) RichRules(rule fireClient.FireInfo, operation string) error {
	if err := c.step("rich " + operation + " " + rule.Address + " " + rule.Port + " " + rule.Strategy); err != nil {
		return err
	}
	if operation == "add" {
		c.richRules = append(c.richRules, rule)
	} else {
		var kept []fireClient.FireInfo
		for _, r := range c.richRules {
			if !(r.Address == rule.Address && r.Port == rule.Port && r.Protocol == rule.Protocol && r.Strategy == rule.Strategy) {
				kept = append(kept, r)
			}
		}
		c.richRules = kept
	}
	return nil
}
func (c *seqFirewallClient) PortForward(info fireClient.Forward, operation string) error {
	return nil
}
func (c *seqFirewallClient) EnableForward() error { return nil }
func (c *seqFirewallClient) step(op string) error {
	c.seq = append(c.seq, op)
	if c.failAt > 0 && len(c.seq) == c.failAt {
		return errors.New("injected failure at " + op)
	}
	return nil
}

func newSeqClient(t *testing.T, name string) *seqFirewallClient {
	t.Helper()
	return &seqFirewallClient{name: name, directPorts: map[string]bool{}}
}

func wantOp(t *testing.T, seq []string, idx int, op string) {
	t.Helper()
	if idx >= len(seq) {
		t.Fatalf("operation #%d missing (got %d ops %v), want %q", idx+1, len(seq), seq, op)
	}
	if seq[idx] != op {
		t.Fatalf("operation #%d = %q, want %q (full seq %v)", idx+1, seq[idx], op, seq)
	}
}

// withFirewallStub swaps the newFirewallClientFn seam for the scripted client
// for the duration of the test.
func withFirewallStub(t *testing.T, c *seqFirewallClient) {
	t.Helper()
	old := newFirewallClientFn
	newFirewallClientFn = func() (firewall.FirewallClient, error) {
		return c, nil
	}
	t.Cleanup(func() { newFirewallClientFn = old })
}

// setupFirewallTestDB wires an in-memory sqlite with the Firewall table so
// OperatePortRule/OperateAddressRule can persist their record bookkeeping.
func setupFirewallTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Firewall{}); err != nil {
		t.Fatalf("migrate %T failed: %v", &model.Firewall{}, err)
	}
	global.DB = db
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
}

func TestUpdatePortRuleMainFlowOrderAndSuccess(t *testing.T) {
	setupFirewallTestDB(t)
	svc := &FirewallService{}
	c := newSeqClient(t, "firewalld")
	c.directPorts["22/tcp"] = true
	withFirewallStub(t, c)

	err := svc.UpdatePortRule(dto.PortRuleUpdate{
		OldRule: dto.PortRuleOperate{Operation: "remove", Port: "22", Protocol: "tcp", Strategy: "accept"},
		NewRule: dto.PortRuleOperate{Operation: "add", Port: "2222", Protocol: "tcp", Strategy: "accept"},
	})
	if err != nil {
		t.Fatalf("UpdatePortRule: %v", err)
	}
	// delete the old rule first (firewalld rejects an already-enabled port on
	// add), then add the new one, then reload
	if len(c.seq) != 3 {
		t.Fatalf("ops = %v, want 3", c.seq)
	}
	wantOp(t, c.seq, 0, "port remove 22/tcp")
	wantOp(t, c.seq, 1, "port add 2222/tcp")
	wantOp(t, c.seq, 2, "reload")
	if c.directPorts["22/tcp"] {
		t.Fatal("old port rule still present after update")
	}
	if !c.directPorts["2222/tcp"] {
		t.Fatal("new port rule missing after update")
	}
}

func TestUpdatePortRuleSameKeyDescriptionEditSucceeds(t *testing.T) {
	setupFirewallTestDB(t)
	svc := &FirewallService{}
	c := newSeqClient(t, "firewalld")
	c.directPorts["22/tcp"] = true
	withFirewallStub(t, c)

	// the frontend edit dialog sends old == new keys for a description-only
	// change; the new add must not collide with a still-present old rule
	err := svc.UpdatePortRule(dto.PortRuleUpdate{
		OldRule: dto.PortRuleOperate{Operation: "remove", Port: "22", Protocol: "tcp", Strategy: "accept"},
		NewRule: dto.PortRuleOperate{Operation: "add", Port: "22", Protocol: "tcp", Strategy: "accept"},
	})
	if err != nil {
		t.Fatalf("UpdatePortRule: %v", err)
	}
	if len(c.seq) != 3 {
		t.Fatalf("ops = %v, want remove + add + reload", c.seq)
	}
	wantOp(t, c.seq, 0, "port remove 22/tcp")
	wantOp(t, c.seq, 1, "port add 22/tcp")
	if !c.directPorts["22/tcp"] {
		t.Fatal("rule should be present after same-key update")
	}
}

func TestUpdatePortRuleNewAddFailsRestoresOld(t *testing.T) {
	setupFirewallTestDB(t)
	svc := &FirewallService{}
	c := newSeqClient(t, "firewalld")
	c.directPorts["22/tcp"] = true
	c.failAt = 2 // the add of the new rule fails
	withFirewallStub(t, c)

	err := svc.UpdatePortRule(dto.PortRuleUpdate{
		OldRule: dto.PortRuleOperate{Operation: "remove", Port: "22", Protocol: "tcp", Strategy: "accept"},
		NewRule: dto.PortRuleOperate{Operation: "add", Port: "2222", Protocol: "tcp", Strategy: "accept"},
	})
	if err == nil {
		t.Fatal("expected error when adding the new rule fails")
	}
	// remove old, failed add new, restore old add
	if len(c.seq) != 3 {
		t.Fatalf("ops = %v, want 3", c.seq)
	}
	wantOp(t, c.seq, 0, "port remove 22/tcp")
	wantOp(t, c.seq, 1, "port add 2222/tcp")
	wantOp(t, c.seq, 2, "port add 22/tcp")
	if !c.directPorts["22/tcp"] {
		t.Fatal("old rule was not restored after the failed add")
	}
	if c.directPorts["2222/tcp"] {
		t.Fatal("failed new rule should not be in place")
	}
}

func TestUpdatePortRuleRichRuleAddFailsRestoresOld(t *testing.T) {
	setupFirewallTestDB(t)
	svc := &FirewallService{}
	c := newSeqClient(t, "firewalld")
	c.richRules = []fireClient.FireInfo{{Address: "1.2.3.4", Port: "22", Protocol: "tcp", Strategy: "drop"}}
	c.failAt = 2 // the add of the new rich rule fails
	withFirewallStub(t, c)

	err := svc.UpdatePortRule(dto.PortRuleUpdate{
		OldRule: dto.PortRuleOperate{Operation: "remove", Port: "22", Protocol: "tcp", Address: "1.2.3.4", Strategy: "drop"},
		NewRule: dto.PortRuleOperate{Operation: "add", Port: "22", Protocol: "tcp", Address: "1.2.3.4", Strategy: "accept"},
	})
	if err == nil {
		t.Fatal("expected error when adding the new rich rule fails")
	}
	// remove old, failed add new, restore old add
	if len(c.seq) != 3 {
		t.Fatalf("ops = %v, want 3", c.seq)
	}
	wantOp(t, c.seq, 0, "rich remove 1.2.3.4 22 drop")
	wantOp(t, c.seq, 1, "rich add 1.2.3.4 22 accept")
	wantOp(t, c.seq, 2, "rich add 1.2.3.4 22 drop")
	if len(c.richRules) != 1 || c.richRules[0].Strategy != "drop" {
		t.Fatalf("rich rules after rollback = %v, want the old drop rule back", c.richRules)
	}
}

func TestUpdatePortRuleNoopOldAddsOnly(t *testing.T) {
	setupFirewallTestDB(t)
	svc := &FirewallService{}
	c := newSeqClient(t, "firewalld")
	withFirewallStub(t, c)

	err := svc.UpdatePortRule(dto.PortRuleUpdate{
		OldRule: dto.PortRuleOperate{Operation: "remove", Protocol: "tcp/udp", Address: "Anywhere"},
		NewRule: dto.PortRuleOperate{Operation: "add", Port: "8080", Protocol: "tcp", Strategy: "accept"},
	})
	if err != nil {
		t.Fatalf("UpdatePortRule: %v", err)
	}
	if len(c.seq) != 2 {
		t.Fatalf("ops = %v, want add + reload", c.seq)
	}
	wantOp(t, c.seq, 0, "port add 8080/tcp")
	wantOp(t, c.seq, 1, "reload")
}

func TestUpdatePortRuleNoopOldAddFailsNoChange(t *testing.T) {
	setupFirewallTestDB(t)
	svc := &FirewallService{}
	c := newSeqClient(t, "firewalld")
	c.failAt = 1 // the add of the new rule fails
	withFirewallStub(t, c)

	err := svc.UpdatePortRule(dto.PortRuleUpdate{
		OldRule: dto.PortRuleOperate{Operation: "remove"},
		NewRule: dto.PortRuleOperate{Operation: "add", Port: "2222", Protocol: "tcp", Strategy: "accept"},
	})
	if err == nil {
		t.Fatal("expected error when adding the new rule fails")
	}
	if len(c.seq) != 1 {
		t.Fatalf("ops = %v, want only the failed add", c.seq)
	}
	if c.directPorts["2222/tcp"] {
		t.Fatal("failed rule should not be in place")
	}
}

func TestUpdateAddrRuleFailureRestoresOld(t *testing.T) {
	setupFirewallTestDB(t)
	svc := &FirewallService{}
	c := newSeqClient(t, "firewalld")
	c.richRules = []fireClient.FireInfo{{Address: "1.2.3.4", Strategy: "drop"}}
	c.failAt = 2 // the add of the new address rule fails
	withFirewallStub(t, c)

	err := svc.UpdateAddrRule(dto.AddrRuleUpdate{
		OldRule: dto.AddrRuleOperate{Operation: "remove", Address: "1.2.3.4", Strategy: "drop"},
		NewRule: dto.AddrRuleOperate{Operation: "add", Address: "1.2.3.4", Strategy: "accept"},
	})
	if err == nil {
		t.Fatal("expected error when adding the new address rule fails")
	}
	if len(c.seq) != 3 {
		t.Fatalf("ops = %v, want 3", c.seq)
	}
	wantOp(t, c.seq, 0, "rich remove 1.2.3.4  drop")
	wantOp(t, c.seq, 1, "rich add 1.2.3.4  accept")
	wantOp(t, c.seq, 2, "rich add 1.2.3.4  drop")
	if len(c.richRules) != 1 || c.richRules[0].Strategy != "drop" {
		t.Fatalf("address rules after rollback = %v, want the old drop rule back", c.richRules)
	}
}

func TestUpdateAddrRuleNoopOldAddsOnly(t *testing.T) {
	setupFirewallTestDB(t)
	svc := &FirewallService{}
	c := newSeqClient(t, "firewalld")
	withFirewallStub(t, c)

	err := svc.UpdateAddrRule(dto.AddrRuleUpdate{
		OldRule: dto.AddrRuleOperate{Operation: "remove"},
		NewRule: dto.AddrRuleOperate{Operation: "add", Address: "1.2.3.4", Strategy: "drop"},
	})
	if err != nil {
		t.Fatalf("UpdateAddrRule: %v", err)
	}
	if len(c.seq) != 2 {
		t.Fatalf("ops = %v, want add + reload", c.seq)
	}
	wantOp(t, c.seq, 0, "rich add 1.2.3.4  drop")
	wantOp(t, c.seq, 1, "reload")
}

func TestBatchOperateRuleCollectsFailures(t *testing.T) {
	setupFirewallTestDB(t)
	svc := &FirewallService{}
	c := newSeqClient(t, "firewalld")
	c.failAt = 2 // the second rule fails
	withFirewallStub(t, c)

	err := svc.BatchOperateRule(dto.BatchRuleOperate{Type: "port", Rules: []dto.PortRuleOperate{
		{Operation: "add", Port: "80", Protocol: "tcp", Strategy: "accept"},
		{Operation: "add", Port: "443", Protocol: "tcp", Strategy: "accept"},
		{Operation: "add", Port: "8080", Protocol: "tcp", Strategy: "accept"},
	}})
	if err == nil {
		t.Fatal("expected partial failure error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "partially failed") {
		t.Fatalf("error should describe the partial failure, got: %v", err)
	}
	if !strings.Contains(msg, "443") {
		t.Fatalf("error should name the failed rule, got: %v", err)
	}
	// rules 1 and 3 succeeded and stay in place; no reload was attempted
	if !c.directPorts["80/tcp"] || !c.directPorts["8080/tcp"] {
		t.Fatalf("successful rules were not kept, state: %v", c.directPorts)
	}
	if c.directPorts["443/tcp"] {
		t.Fatal("failed rule should not be in place")
	}
	if strings.Contains(strings.Join(c.seq, ","), "reload") {
		t.Fatalf("no reload may run after a partial failure, seq: %v", c.seq)
	}
}

func TestBatchOperateRuleAllSuccessReloads(t *testing.T) {
	setupFirewallTestDB(t)
	svc := &FirewallService{}
	c := newSeqClient(t, "firewalld")
	withFirewallStub(t, c)

	err := svc.BatchOperateRule(dto.BatchRuleOperate{Type: "address", Rules: []dto.PortRuleOperate{
		{Operation: "add", Address: "1.2.3.4", Strategy: "drop"},
		{Operation: "add", Address: "5.6.7.8", Strategy: "drop"},
	}})
	if err != nil {
		t.Fatalf("BatchOperateRule: %v", err)
	}
	if len(c.seq) != 3 {
		t.Fatalf("ops = %v, want 2 adds + reload", c.seq)
	}
	wantOp(t, c.seq, 2, "reload")
}
