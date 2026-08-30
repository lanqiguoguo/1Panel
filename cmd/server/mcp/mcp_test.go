package mcp

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultMcpComposePinsSupergatewayImage(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(DefaultMcpCompose, &compose); err != nil {
		t.Fatalf("unmarshal default MCP compose: %v", err)
	}

	service, ok := compose.Services["mcp-server"]
	if !ok {
		t.Fatal("default MCP compose has no mcp-server service")
	}

	const wantImage = "supercorp/supergateway:3.4.3@sha256:095acf4471e142553c1a5514aa5e480abbc5885d00549d4a3481cc70eac53889"
	if service.Image != wantImage {
		t.Errorf("mcp-server image = %q, want %q", service.Image, wantImage)
	}
}
