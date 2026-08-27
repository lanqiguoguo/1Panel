package captcha

import (
	"strings"
	"testing"
)

// TestCreateCaptcha guards the generated captcha image and id: every call
// must yield a non-empty id and a valid base64 data-url image, regardless of
// the (hardened) NoiseCount/Length settings.
func TestCreateCaptcha(t *testing.T) {
	for i := 0; i < 5; i++ {
		resp, err := CreateCaptcha()
		if err != nil {
			t.Fatalf("CreateCaptcha() error: %v", err)
		}
		if resp == nil {
			t.Fatal("CreateCaptcha() returned nil response")
		}
		if resp.CaptchaID == "" {
			t.Fatal("CreateCaptcha() returned empty CaptchaID")
		}
		if !strings.HasPrefix(resp.ImagePath, "data:image/png;base64,") {
			t.Fatalf("ImagePath has unexpected prefix: %q", resp.ImagePath)
		}
	}
}
