package nginx

import "strings"

// ValidNginxParamValue reports whether s can be embedded as a parameter of a
// single nginx directive without changing the structure of the generated
// config file. ';' terminates the current directive, '{' and '}' open or
// close blocks, '#' starts a comment that swallows the rest of the line, and
// newlines/CR/NUL split or corrupt lines. Any of them would let a caller
// inject a second directive into the same block.
//
// Everything else is legal nginx parameter content and preserved: variables
// ('$host', '$uri'), URLs ('http://127.0.0.1:8080/'), regexes used by
// rewrite/location ('^~', '^/api/(.*)$'), paths, IPv6 ('[::1]:8080') and
// plain values ('on', 'off').
//
// The empty string is considered valid: callers decide requiredness from
// their own validation rules (e.g. proxyPass/proxyHost are validate
// "required", while proxySSLName/match/replaces may legitimately be empty).
func ValidNginxParamValue(s string) bool {
	if s == "" {
		return true
	}
	return !strings.ContainsAny(s, ";#{}\r\n\x00")
}
