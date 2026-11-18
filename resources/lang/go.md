# Go Security PoC Adapter

## 1. Target Resolution & In-Process HTTP Isolation
- Copy Go tests inside `S/sandbox-fix/` (or run via `--cwd "$S/sandbox-fix"` in remediation) using `net/http/httptest.NewRecorder()` so zero external sockets are opened.
- Keep `GOPROXY=off` (automatically set by `vs.py`).

## 2. Go PoC Template (`bughunt_sec1_test.go`)
```go
package routes

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestControl_AuthorizedOwnerCanRead(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/invoices/INV-101", nil)
	req.Header.Set("X-User-ID", "user-a")
	rr := httptest.NewRecorder()
	InvoiceHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for authorized owner, got %d", rr.Code)
	}
}

func TestUnauthorized_CrossAccountIDORBlocked(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/invoices/INV-101", nil)
	req.Header.Set("X-User-ID", "user-b")
	rr := httptest.NewRecorder()
	InvoiceHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("IDOR breach: expected 403 for user-b, got %d", rr.Code)
	}
}
```
- For `RACE_DOUBLE_SPEND`, run with `go test -race` and `sync.WaitGroup` + `startCh := make(chan struct{})` (`close(startCh)` to release goroutines simultaneously).
