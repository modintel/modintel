package api

import "testing"

func TestShortUserAgent(t *testing.T) {
	if got := shortUserAgent(""); got != "Unknown device" {
		t.Fatalf("expected fallback label, got %q", got)
	}

	short := "Mozilla/5.0"
	if got := shortUserAgent(short); got != short {
		t.Fatalf("expected unchanged short UA, got %q", got)
	}

	longUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36 ExtraData"
	got := shortUserAgent(longUA)
	if len(got) > 75 {
		t.Fatalf("expected truncated UA <= 75 chars, got %d", len(got))
	}
	if got == longUA {
		t.Fatal("expected long UA to be truncated")
	}
}
