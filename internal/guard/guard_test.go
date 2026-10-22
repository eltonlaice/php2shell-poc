package guard

import "testing"

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		public  bool
		wantErr bool
	}{
		{"loopback", "http://127.0.0.1:18080", false, false},
		{"localhost", "http://localhost:18080", false, false},
		{"private", "http://10.1.2.3", false, false},
		{"public", "http://8.8.8.8", false, true},
		{"public allowed", "http://8.8.8.8", true, false},
		{"bad scheme", "ftp://127.0.0.1", false, true},
		{"no host", "http://", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(tt.target, tt.public)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Check(%q, %v) error = %v, wantErr %v", tt.target, tt.public, err, tt.wantErr)
			}
		})
	}
}
