package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		want       string
		wantErr    error
	}{
		{
			name:       "valid API key",
			authHeader: "ApiKey abc123",
			want:       "abc123",
			wantErr:    nil,
		},
		{
			name:       "missing authorization header",
			authHeader: "",
			want:       "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name:       "invalid authentication scheme",
			authHeader: "Bearer abc123",
			want:       "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name:       "missing API key",
			authHeader: "ApiKey",
			want:       "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name:       "empty API key",
			authHeader: "ApiKey ",
			want:       "",
			wantErr:    nil,
		},
		{
			name:       "extra spaces",
			authHeader: "ApiKey abc123 extra",
			want:       "abc123",
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			got, err := GetAPIKey(headers)

			if got != tt.want {
				t.Errorf("GetAPIKey() = %q, want %q", got, tt.want)
			}

			if tt.wantErr != nil {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
			}
		})
	}
}
