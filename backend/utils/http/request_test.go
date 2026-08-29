package http

import (
	"errors"
	"io"
	stdhttp "net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*stdhttp.Request) (*stdhttp.Response, error)

func (f roundTripFunc) RoundTrip(req *stdhttp.Request) (*stdhttp.Response, error) {
	return f(req)
}

type trackingBody struct {
	reader     io.Reader
	closeCalls int32
}

func (b *trackingBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *trackingBody) Close() error {
	atomic.AddInt32(&b.closeCalls, 1)
	return nil
}

type readError struct{}

func (readError) Read([]byte) (int, error) {
	return 0, errors.New("read body failed")
}

func TestHandleGetWithClientClosesResponseBody(t *testing.T) {
	requestErr := errors.New("request failed")
	tests := []struct {
		name       string
		statusCode int
		status     string
		body       io.Reader
		roundTrip  error
		wantStatus int
		wantBody   string
		wantErr    error
	}{
		{
			name:       "ok",
			statusCode: stdhttp.StatusOK,
			status:     "200 OK",
			body:       strings.NewReader("response body"),
			wantStatus: stdhttp.StatusOK,
			wantBody:   "response body",
		},
		{
			name:       "non-200",
			statusCode: stdhttp.StatusBadGateway,
			status:     "502 Bad Gateway",
			body:       strings.NewReader("error body"),
			wantErr:    errors.New("502 Bad Gateway"),
		},
		{
			name:       "read error",
			statusCode: stdhttp.StatusOK,
			status:     "200 OK",
			body:       readError{},
			wantErr:    errors.New("read body failed"),
		},
		{
			name:      "request error",
			roundTrip: requestErr,
			wantErr:   requestErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var responseBody *trackingBody
			client := &stdhttp.Client{
				Transport: roundTripFunc(func(req *stdhttp.Request) (*stdhttp.Response, error) {
					if tt.roundTrip != nil {
						return nil, tt.roundTrip
					}
					responseBody = &trackingBody{reader: tt.body}
					return &stdhttp.Response{
						StatusCode: tt.statusCode,
						Status:     tt.status,
						Body:       responseBody,
						Header:     make(stdhttp.Header),
						Request:    req,
					}, nil
				}),
			}

			statusCode, body, err := handleGetWithClient("http://example.test", stdhttp.MethodGet, 1, client)
			if statusCode != tt.wantStatus {
				t.Errorf("status code = %d, want %d", statusCode, tt.wantStatus)
			}
			if string(body) != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if err == nil || err.Error() != tt.wantErr.Error() && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
			if responseBody != nil && atomic.LoadInt32(&responseBody.closeCalls) != 1 {
				t.Errorf("response body close calls = %d, want 1", responseBody.closeCalls)
			}
		})
	}
}
