package nginx

import "testing"

func TestValidNginxParamValue(t *testing.T) {
	valid := []string{
		"",
		"http://127.0.0.1:8080",
		"https://example.com",
		"http://1panel.cloud/",
		"127.0.0.1:8080",
		"unix:/www/sites/example/php-pool/php-fpm.sock",
		"$host",
		"$proxy_host",
		"$host$uri$is_args$args",
		"^/api/(.*)$",
		"^~",
		"~",
		"=^/admin$",
		"/var/www/site",
		"/www/sites/demo/index",
		"[::1]:8080",
		"on",
		"off",
		"10m",
		"1d",
		"301",
		"404",
		"js,css,png,jpg",
		"permanent",
		"redirect",
		"Strict-Transport-Security",
		"max-age=31536000",
		"*.example.com",
	}
	for _, s := range valid {
		if !ValidNginxParamValue(s) {
			t.Errorf("ValidNginxParamValue(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"http://x; return 403;",
		"http://x;return 403;",
		"a#b",
		"a# b",
		"a{b",
		"a}b",
		"a\nb",
		"a\rb",
		"a\x00b",
		"http://x; deny all;",
		";",
		"{",
		"}",
		"#",
		"http://x\ninclude /etc/nginx/evil.conf;",
	}
	for _, s := range invalid {
		if ValidNginxParamValue(s) {
			t.Errorf("ValidNginxParamValue(%q) = true, want false", s)
		}
	}
}
