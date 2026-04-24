package scanner

import "testing"

func TestParseCustomPorts_SingleAndRange(t *testing.T) {
	got, err := ParseCustomPorts("22,80-82,443")
	if err != nil {
		t.Fatalf("beklenmedik hata: %v", err)
	}
	want := []string{"22", "80", "81", "82", "443"}
	if len(got) != len(want) {
		t.Fatalf("uzunluk: got=%d want=%d (%v)", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("idx=%d: got=%q want=%q", i, got[i], v)
		}
	}
}

func TestParseCustomPorts_Empty(t *testing.T) {
	ports, err := ParseCustomPorts("")
	if err != nil {
		t.Fatalf("beklenmedik hata: %v", err)
	}
	if ports != nil {
		t.Errorf("boş girdi için nil bekleniyordu: %v", ports)
	}
}

func TestParseCustomPorts_InvalidValues(t *testing.T) {
	cases := []string{
		"abc",
		"0",
		"70000",
		"100-50",
		"10-abc",
	}
	for _, in := range cases {
		if _, err := ParseCustomPorts(in); err == nil {
			t.Errorf("girdi %q için hata bekleniyordu", in)
		}
	}
}

func TestGetProfile_KnownNames(t *testing.T) {
	cases := []struct {
		name    string
		wantKey string
	}{
		{"quick", "quick"},
		{"full", "full"},
		{"stealth", "stealth"},
		{"standard", "standard"},
		{"", "standard"},            // default
		{"SomeUnknown", "standard"}, // default
	}
	for _, c := range cases {
		p := GetProfile(c.name)
		if p.Name != c.wantKey {
			t.Errorf("GetProfile(%q).Name = %q, want %q", c.name, p.Name, c.wantKey)
		}
		if len(p.Ports) == 0 {
			t.Errorf("GetProfile(%q): port listesi boş", c.name)
		}
		if p.TimeoutMs <= 0 {
			t.Errorf("GetProfile(%q): geçersiz timeout %d", c.name, p.TimeoutMs)
		}
	}
}
