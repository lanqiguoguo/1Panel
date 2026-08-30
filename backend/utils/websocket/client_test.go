package websocket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

// TestWsClientReadLimit proves NewWsClient caps the client -> server message
// size: a message larger than constant.WsReadLimit must fail the server read
// (ErrReadLimit) and the client must observe a close with code 1009
// (CloseMessageTooBig). The server -> client direction is not limited: the
// read limit only bounds what the peer may send us.
func TestWsClientReadLimit(t *testing.T) {
	global.LOG = logrus.New()

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	serverCh := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		serverCh <- ws
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer clientConn.Close()
	serverConn := <-serverCh
	defer serverConn.Close()

	client := NewWsClient("test", serverConn)
	done := make(chan struct{})
	go func() {
		client.Read()
		close(done)
	}()

	// A small message must flow through untouched: the read loop keeps running
	// (it would have exited if the small message had tripped the limit).
	if err := clientConn.WriteMessage(websocket.TextMessage, []byte(`{"type":""}`)); err != nil {
		t.Fatalf("write small message: %v", err)
	}
	select {
	case <-done:
		t.Fatal("read loop exited on a small message: read limit too tight")
	case <-time.After(300 * time.Millisecond):
	}

	// An oversized message must terminate the read loop and close with 1009.
	big := make([]byte, constant.WsReadLimit+1)
	if err := clientConn.WriteMessage(websocket.TextMessage, big); err != nil {
		t.Fatalf("write oversized message: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("server read loop did not terminate after oversized message")
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = clientConn.ReadMessage()
	closeErr, ok := err.(*websocket.CloseError)
	if !ok {
		t.Fatalf("expected *websocket.CloseError after oversized message, got %v", err)
	}
	if closeErr.Code != websocket.CloseMessageTooBig {
		t.Fatalf("close code = %d, want %d (1009)", closeErr.Code, websocket.CloseMessageTooBig)
	}
}
