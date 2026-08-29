package service

import (
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
)

// forwardRuleParams carries the input fields for validateForwardRule without
// depending on the anonymous struct inside dto.ForwardRuleOperate.
type forwardRuleParams struct {
	num        string
	protocol   string
	port       string
	targetIP   string
	targetPort string
}

func TestValidateForwardRule(t *testing.T) {
	valid := forwardRuleParams{num: "1", protocol: "tcp", port: "8080", targetIP: "192.168.1.1", targetPort: "80"}

	testCases := []struct {
		name    string
		params  forwardRuleParams
		wantErr bool
	}{
		{"valid all fields", valid, false},
		{"valid udp", forwardRuleParams{protocol: "udp", port: "53", targetIP: "10.0.0.1", targetPort: "53"}, false},
		{"valid tcp/udp", forwardRuleParams{protocol: "tcp/udp", port: "443", targetIP: "127.0.0.1", targetPort: "443"}, false},
		{"valid empty targetIP", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "", targetPort: "80"}, false},
		{"valid localhost targetIP", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "localhost", targetPort: "80"}, false},
		{"valid 127.0.0.1 targetIP", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "127.0.0.1", targetPort: "80"}, false},
		{"valid max port", forwardRuleParams{protocol: "tcp", port: "65535", targetIP: "1.2.3.4", targetPort: "65535"}, false},
		{"valid num empty", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "1.2.3.4", targetPort: "80"}, false},

		{"invalid port command injection", forwardRuleParams{protocol: "tcp", port: "; id;", targetIP: "1.2.3.4", targetPort: "80"}, true},
		{"invalid port trailing semicolon", forwardRuleParams{protocol: "tcp", port: "8080;", targetIP: "1.2.3.4", targetPort: "80"}, true},
		{"invalid port subtitution", forwardRuleParams{protocol: "tcp", port: "$(id)", targetIP: "1.2.3.4", targetPort: "80"}, true},
		{"invalid port empty", forwardRuleParams{protocol: "tcp", port: "", targetIP: "1.2.3.4", targetPort: "80"}, true},
		{"invalid port zero", forwardRuleParams{protocol: "tcp", port: "0", targetIP: "1.2.3.4", targetPort: "80"}, true},
		{"invalid port too large", forwardRuleParams{protocol: "tcp", port: "65536", targetIP: "1.2.3.4", targetPort: "80"}, true},
		{"invalid port non numeric", forwardRuleParams{protocol: "tcp", port: "abc", targetIP: "1.2.3.4", targetPort: "80"}, true},

		{"invalid targetIP command substitution", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "$(id)", targetPort: "80"}, true},
		{"invalid targetIP command injection", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "1.2.3.4; touch /tmp/x", targetPort: "80"}, true},
		{"invalid targetIP non ip", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "not-an-ip", targetPort: "80"}, true},
		{"invalid targetIP ipv6", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "2001:db8::1", targetPort: "80"}, true},
		{"invalid targetIP partial ipv4", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "1.2.3", targetPort: "80"}, true},
		{"invalid targetIP out of range octet", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "256.1.1.1", targetPort: "80"}, true},

		{"invalid targetPort non numeric", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "1.2.3.4", targetPort: "abc"}, true},
		{"invalid targetPort injection", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "1.2.3.4", targetPort: "80;rm -rf /"}, true},
		{"invalid targetPort empty", forwardRuleParams{protocol: "tcp", port: "8080", targetIP: "1.2.3.4", targetPort: ""}, true},

		{"invalid num non numeric", forwardRuleParams{num: "abc", protocol: "tcp", port: "8080", targetIP: "1.2.3.4", targetPort: "80"}, true},
		{"invalid num injection", forwardRuleParams{num: "1;reboot", protocol: "tcp", port: "8080", targetIP: "1.2.3.4", targetPort: "80"}, true},

		{"invalid protocol icmp", forwardRuleParams{protocol: "icmp", port: "8080", targetIP: "1.2.3.4", targetPort: "80"}, true},
		{"invalid protocol injection", forwardRuleParams{protocol: "tcp;id", port: "8080", targetIP: "1.2.3.4", targetPort: "80"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateForwardRule(tc.params.num, tc.params.protocol, tc.params.port, tc.params.targetIP, tc.params.targetPort)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %s but got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for %s but got %v", tc.name, err)
			}
		})
	}
}

// forwardRulesElem mirrors the anonymous element type of
// dto.ForwardRuleOperate.Rules so we can build requests for validateForwardRules.
func forwardRulesElem(op, num, proto, port, tip, tport string) struct {
	Operation  string `json:"operation" validate:"required,oneof=add remove"`
	Num        string `json:"num"`
	Protocol   string `json:"protocol" validate:"required,oneof=tcp udp tcp/udp"`
	Port       string `json:"port" validate:"required"`
	TargetIP   string `json:"targetIP"`
	TargetPort string `json:"targetPort" validate:"required"`
} {
	return struct {
		Operation  string `json:"operation" validate:"required,oneof=add remove"`
		Num        string `json:"num"`
		Protocol   string `json:"protocol" validate:"required,oneof=tcp udp tcp/udp"`
		Port       string `json:"port" validate:"required"`
		TargetIP   string `json:"targetIP"`
		TargetPort string `json:"targetPort" validate:"required"`
	}{Operation: op, Num: num, Protocol: proto, Port: port, TargetIP: tip, TargetPort: tport}
}

func forwardReq(elems ...struct {
	Operation  string `json:"operation" validate:"required,oneof=add remove"`
	Num        string `json:"num"`
	Protocol   string `json:"protocol" validate:"required,oneof=tcp udp tcp/udp"`
	Port       string `json:"port" validate:"required"`
	TargetIP   string `json:"targetIP"`
	TargetPort string `json:"targetPort" validate:"required"`
}) dto.ForwardRuleOperate {
	return dto.ForwardRuleOperate{Rules: elems}
}

func TestValidateForwardRules(t *testing.T) {
	valid := forwardRulesElem("add", "", "tcp", "8080", "192.168.1.1", "80")

	testCases := []struct {
		name    string
		req     dto.ForwardRuleOperate
		wantErr bool
	}{
		{"empty rules passes (no-op)", dto.ForwardRuleOperate{}, false},
		{"single valid rule", forwardReq(valid), false},
		{"multiple valid rules", forwardReq(valid, forwardRulesElem("remove", "1", "udp", "53", "localhost", "53")), false},
		{"single invalid rule", forwardReq(forwardRulesElem("add", "", "tcp", "; id;", "1.2.3.4", "80")), true},
		{"invalid rule among valid ones", forwardReq(valid, forwardRulesElem("add", "", "tcp", "8080", "$(id)", "80")), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateForwardRules(tc.req)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %s but got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for %s but got %v", tc.name, err)
			}
		})
	}
}
