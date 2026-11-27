package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/redact"
)

// TestRoundTripRedactsAuthMaterialBeforeSend is the #11 acceptance test: a tool
// output carrying an NT hash never reaches the provider, and the llm record holds
// the redacted bytes because the recorder snapshots after the filter.
func TestRoundTripRedactsAuthMaterialBeforeSend(t *testing.T) {
	const hash = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
	body := `{"messages":[{"role":"user","content":"Administrator:500:` + hash + `:::"}]}`

	var sent string
	base := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		sent = string(b)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}}, nil
	})

	ctx, capt := llmrec.NewCapture(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://provider.test/v1/chat", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (quotaAwareTransport{base: base}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if strings.Contains(sent, "31d6cfe0d16ae931b73c59d7e0c089c0") || !strings.Contains(sent, redact.PlaceholderHash) {
		t.Fatalf("hash reached the provider: %s", sent)
	}
	if captured := capt.RawRequest(); strings.Contains(captured, "31d6cfe0d16ae931b73c59d7e0c089c0") {
		t.Fatalf("llm record holds the hash: %s", captured)
	}
	var v any
	if err := json.Unmarshal([]byte(sent), &v); err != nil {
		t.Fatalf("redaction broke the request JSON: %v (%s)", err, sent)
	}
	if req.ContentLength != int64(len(sent)) {
		t.Fatalf("ContentLength = %d, sent %d bytes", req.ContentLength, len(sent))
	}
}

func TestRoundTripSendsAuthMaterialWhenTaskOptedOut(t *testing.T) {
	const hash = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
	body := `{"messages":[{"role":"user","content":"` + hash + `"}]}`

	var sent string
	base := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		sent = string(b)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}}, nil
	})

	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 7, SendAuthMaterial: true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://provider.test/v1/chat", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (quotaAwareTransport{base: base}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if sent != body {
		t.Fatalf("opted-out task got a rewritten body:\n in: %s\nout: %s", body, sent)
	}
}

func TestRoundTripLeavesCleanBodyByteIdentical(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"10.20.30.10:445 open, password policy read"}]}`
	var sent string
	base := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		sent = string(b)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}}, nil
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://provider.test/v1/chat", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (quotaAwareTransport{base: base}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if sent != body {
		t.Fatalf("clean body rewritten:\n in: %s\nout: %s", body, sent)
	}
}

func TestSendAuthMaterialFailsClosedWithoutStore(t *testing.T) {
	if sendAuthMaterialOn(nil, 41) {
		t.Fatal("nil store enabled auth material")
	}
}
