package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/i18n"
	"github.com/1Panel-dev/1Panel/backend/utils/nginx/components"
	"github.com/1Panel-dev/1Panel/backend/utils/nginx/parser"
)

// validateBindDomainIPs gates the BindDomain/UpdateBindDomain flows of MCP
// servers and AI (Ollama) tools. Those proxies expose unauthenticated services
// (SSE tool execution, model pull/remove, inference), so the IP whitelist is
// mandatory. This test does not need a database: the validators only parse the
// request field and build buserr values.

func TestValidateBindDomainIPs(t *testing.T) {
	i18n.Init()

	isAllowIPsRequired := func(err error) bool {
		if err == nil {
			return false
		}
		var be buserr.BusinessError
		return errors.As(err, &be) && be.Msg == "ErrAllowIPsRequired"
	}

	t.Run("empty list is rejected with ErrAllowIPsRequired", func(t *testing.T) {
		for _, in := range []string{"", "   ", "\n", " \n \n "} {
			got, err := validateBindDomainIPs(in)
			if !isAllowIPsRequired(err) {
				t.Fatalf("validateBindDomainIPs(%q) error = %v, want ErrAllowIPsRequired", in, err)
			}
			if got != nil {
				t.Fatalf("validateBindDomainIPs(%q) = %v, want nil", in, got)
			}
		}
	})

	t.Run("error message resolves from i18n bundles", func(t *testing.T) {
		i18n.UseI18nForCmd("en")
		if msg := buserr.New("ErrAllowIPsRequired").Error(); !strings.Contains(msg, "whitelist") {
			t.Fatalf("en message = %q, want it to mention the whitelist", msg)
		}
		i18n.UseI18nForCmd("zh")
		if msg := buserr.New("ErrAllowIPsRequired").Error(); !strings.Contains(msg, "白名单") {
			t.Fatalf("zh message = %q, want it to mention 白名单", msg)
		}
		i18n.UseI18nForCmd("en")
	})

	t.Run("valid lists pass through to HandleIPList", func(t *testing.T) {
		cases := map[string][]string{
			"192.168.1.1\n":                {"192.168.1.1"},
			"10.0.0.0/8":                   {"10.0.0.0/8"},
			"2001:db8::1":                  {"2001:db8::1"},
			"fd00::/8":                     {"fd00::/8"},
			"192.168.1.1\n10.0.0.0/8\n":    {"192.168.1.1", "10.0.0.0/8"},
			"192.168.1.1\n\n2001:db8::1\n": {"192.168.1.1", "2001:db8::1"},
		}
		for in, want := range cases {
			got, err := validateBindDomainIPs(in)
			if err != nil {
				t.Fatalf("validateBindDomainIPs(%q) failed: %v", in, err)
			}
			if len(got) != len(want) {
				t.Fatalf("validateBindDomainIPs(%q) = %v, want %v", in, got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("validateBindDomainIPs(%q) = %v, want %v", in, got, want)
				}
			}
		}
	})

	t.Run("invalid entries still fail with ErrParseIP", func(t *testing.T) {
		var be buserr.BusinessError
		if _, err := validateBindDomainIPs("192.168.1.1\nnot-an-ip"); err == nil || !errors.As(err, &be) || be.Msg != "ErrParseIP" {
			t.Fatalf("validateBindDomainIPs(invalid) error = %v, want ErrParseIP", err)
		}
	})
}

// applyAllowIPs is the single place deciding the nginx content written by
// ConfigAllowIPs. The assertions run against a parsed server block so the
// written allow/deny set (and the trailing `deny all`) is verified without a
// database, an nginx installation or a running container.

func newTestServer(t *testing.T) *components.Server {
	t.Helper()
	config, err := parser.NewStringParser(`server {
    listen 80;
    server_name example.com;
    location / {
        proxy_pass http://127.0.0.1:9000;
    }
}`).Parse()
	if err != nil {
		t.Fatalf("parse test server failed: %v", err)
	}
	servers := config.FindServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	return servers[0]
}

func serverDirectives(server *components.Server) map[string][]string {
	res := map[string][]string{}
	for _, dir := range server.GetDirectives() {
		name := dir.GetName()
		if name == "allow" || name == "deny" {
			res[name] = append(res[name], strings.Join(dir.GetParameters(), " "))
		}
	}
	return res
}

func TestApplyAllowIPs(t *testing.T) {
	t.Run("whitelist writes allow entries plus deny all", func(t *testing.T) {
		server := newTestServer(t)
		applyAllowIPs(server, []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::1", "fd00::/8"})
		got := serverDirectives(server)
		wantAllow := []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::1", "fd00::/8"}
		if strings.Join(got["allow"], ",") != strings.Join(wantAllow, ",") {
			t.Fatalf("allow directives = %v, want %v", got["allow"], wantAllow)
		}
		if strings.Join(got["deny"], ",") != "all" {
			t.Fatalf("deny directives = %v, want [all]", got["deny"])
		}
	})

	t.Run("previous rules are fully replaced", func(t *testing.T) {
		server := newTestServer(t)
		applyAllowIPs(server, []string{"192.168.1.1"})
		applyAllowIPs(server, []string{"10.0.0.1"})
		got := serverDirectives(server)
		if strings.Join(got["allow"], ",") != "10.0.0.1" {
			t.Fatalf("allow directives = %v, want [10.0.0.1] (old rules must be removed)", got["allow"])
		}
		if strings.Join(got["deny"], ",") != "all" {
			t.Fatalf("deny directives = %v, want [all]", got["deny"])
		}
	})

	t.Run("empty list clears every rule, matching legacy ConfigAllowIPs", func(t *testing.T) {
		// Legacy semantics kept on purpose: with the new validators the empty
		// list is rejected before ConfigAllowIPs is ever reached; passing nil
		// here only documents that the writer is a pure "replace rules" op.
		server := newTestServer(t)
		applyAllowIPs(server, []string{"192.168.1.1"})
		applyAllowIPs(server, nil)
		got := serverDirectives(server)
		if len(got["allow"]) != 0 || len(got["deny"]) != 0 {
			t.Fatalf("allow/deny directives = %v, want none", got)
		}
	})

	t.Run("server-level rules stay outside the location block", func(t *testing.T) {
		// The MCP proxy include (sse.conf `location ^~ /sse`) carries no access
		// directives of its own; nginx merges server-level allow/deny into such
		// locations. The rules must therefore be written at server level, never
		// inside `location /`.
		server := newTestServer(t)
		applyAllowIPs(server, []string{"192.168.1.1"})
		for _, dir := range server.GetDirectives() {
			if dir.GetName() != "location" {
				continue
			}
			for _, inner := range dir.GetBlock().GetDirectives() {
				if inner.GetName() == "allow" || inner.GetName() == "deny" {
					t.Fatalf("access directive %s leaked into location block", inner.GetName())
				}
			}
		}
	})
}
