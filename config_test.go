package smbfs

import (
	"testing"
	"time"
)

func TestConfig_setDefaults(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected *Config
	}{
		{
			name:   "empty config gets all defaults",
			config: &Config{},
			expected: &Config{
				Port:            445,
				MaxIdle:         5,
				MaxOpen:         10,
				IdleTimeout:     5 * time.Minute,
				ConnTimeout:     30 * time.Second,
				OpTimeout:       60 * time.Second,
				ReadBufferSize:  64 * 1024,
				WriteBufferSize: 64 * 1024,
				CacheTTL:        30 * time.Second,
			},
		},
		{
			name: "custom values are preserved",
			config: &Config{
				Port:      10445,
				MaxIdle:   10,
				MaxOpen:   20,
				OpTimeout: 120 * time.Second,
			},
			expected: &Config{
				Port:            10445,
				MaxIdle:         10,
				MaxOpen:         20,
				IdleTimeout:     5 * time.Minute,
				ConnTimeout:     30 * time.Second,
				OpTimeout:       120 * time.Second,
				ReadBufferSize:  64 * 1024,
				WriteBufferSize: 64 * 1024,
				CacheTTL:        30 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.setDefaults()

			if tt.config.Port != tt.expected.Port {
				t.Errorf("Port = %d, want %d", tt.config.Port, tt.expected.Port)
			}
			if tt.config.MaxIdle != tt.expected.MaxIdle {
				t.Errorf("MaxIdle = %d, want %d", tt.config.MaxIdle, tt.expected.MaxIdle)
			}
			if tt.config.MaxOpen != tt.expected.MaxOpen {
				t.Errorf("MaxOpen = %d, want %d", tt.config.MaxOpen, tt.expected.MaxOpen)
			}
			if tt.config.IdleTimeout != tt.expected.IdleTimeout {
				t.Errorf("IdleTimeout = %v, want %v", tt.config.IdleTimeout, tt.expected.IdleTimeout)
			}
			if tt.config.ConnTimeout != tt.expected.ConnTimeout {
				t.Errorf("ConnTimeout = %v, want %v", tt.config.ConnTimeout, tt.expected.ConnTimeout)
			}
			if tt.config.OpTimeout != tt.expected.OpTimeout {
				t.Errorf("OpTimeout = %v, want %v", tt.config.OpTimeout, tt.expected.OpTimeout)
			}
			if tt.config.ReadBufferSize != tt.expected.ReadBufferSize {
				t.Errorf("ReadBufferSize = %d, want %d", tt.config.ReadBufferSize, tt.expected.ReadBufferSize)
			}
			if tt.config.WriteBufferSize != tt.expected.WriteBufferSize {
				t.Errorf("WriteBufferSize = %d, want %d", tt.config.WriteBufferSize, tt.expected.WriteBufferSize)
			}
			if tt.config.CacheTTL != tt.expected.CacheTTL {
				t.Errorf("CacheTTL = %v, want %v", tt.config.CacheTTL, tt.expected.CacheTTL)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with username/password",
			config: &Config{
				Server:   "server.example.com",
				Share:    "myshare",
				Username: "user",
				Password: "pass",
				Port:     445,
			},
			wantErr: false,
		},
		{
			name: "valid config with guest access",
			config: &Config{
				Server:      "server.example.com",
				Share:       "public",
				GuestAccess: true,
				Port:        445,
			},
			wantErr: false,
		},
		{
			name: "valid config with Kerberos",
			config: &Config{
				Server:      "server.example.com",
				Share:       "myshare",
				Username:    "user",
				UseKerberos: true,
				Port:        445,
			},
			wantErr: false,
		},
		{
			name: "missing server",
			config: &Config{
				Share:    "myshare",
				Username: "user",
				Password: "pass",
				Port:     445,
			},
			wantErr: true,
			errMsg:  "server is required",
		},
		{
			name: "missing share",
			config: &Config{
				Server:   "server.example.com",
				Username: "user",
				Password: "pass",
				Port:     445,
			},
			wantErr: true,
			errMsg:  "share is required",
		},
		{
			name: "invalid port - too low",
			config: &Config{
				Server:   "server.example.com",
				Share:    "myshare",
				Username: "user",
				Password: "pass",
				Port:     0,
			},
			wantErr: true,
			errMsg:  "invalid port: 0",
		},
		{
			name: "invalid port - too high",
			config: &Config{
				Server:   "server.example.com",
				Share:    "myshare",
				Username: "user",
				Password: "pass",
				Port:     70000,
			},
			wantErr: true,
			errMsg:  "invalid port: 70000",
		},
		{
			name: "missing username for non-guest",
			config: &Config{
				Server: "server.example.com",
				Share:  "myshare",
				Port:   445,
			},
			wantErr: true,
			errMsg:  "username is required for non-guest access",
		},
		{
			name: "missing password for non-Kerberos",
			config: &Config{
				Server:   "server.example.com",
				Share:    "myshare",
				Username: "user",
				Port:     445,
			},
			wantErr: true,
			errMsg:  "password is required when not using Kerberos",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("Validate() error = %q, want %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestParseConnectionString(t *testing.T) {
	tests := []struct {
		name     string
		connStr  string
		wantErr  bool
		expected *Config
	}{
		{
			name:    "basic connection string",
			connStr: "smb://user:pass@server.example.com/share",
			wantErr: false,
			expected: &Config{
				Server:   "server.example.com",
				Share:    "share",
				Username: "user",
				Password: "pass",
				Port:     445,
			},
		},
		{
			name:    "connection string with custom port",
			connStr: "smb://user:pass@server.example.com:10445/share",
			wantErr: false,
			expected: &Config{
				Server:   "server.example.com",
				Share:    "share",
				Username: "user",
				Password: "pass",
				Port:     10445,
			},
		},
		{
			name:    "connection string with domain%5Cuser (URL encoded backslash)",
			connStr: "smb://DOMAIN%5Cuser:pass@server.example.com/share",
			wantErr: false,
			expected: &Config{
				Server:   "server.example.com",
				Share:    "share",
				Username: "user",
				Password: "pass",
				Domain:   "DOMAIN",
				Port:     445,
			},
		},
		{
			name:    "guest access (no credentials)",
			connStr: "smb://server.example.com/public",
			wantErr: false,
			expected: &Config{
				Server:      "server.example.com",
				Share:       "public",
				GuestAccess: true,
				Port:        445,
			},
		},
		{
			name:    "connection string with path after share",
			connStr: "smb://user:pass@server.example.com/share/path/to/dir",
			wantErr: false,
			expected: &Config{
				Server:   "server.example.com",
				Share:    "share",
				Username: "user",
				Password: "pass",
				Port:     445,
			},
		},
		{
			name:    "invalid scheme",
			connStr: "http://server.example.com/share",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			connStr: "not a valid url",
			wantErr: true,
		},
		{
			name:    "invalid port",
			connStr: "smb://user:pass@server.example.com:invalid/share",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConnectionString(tt.connStr)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseConnectionString() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseConnectionString() unexpected error = %v", err)
			}

			if cfg.Server != tt.expected.Server {
				t.Errorf("Server = %q, want %q", cfg.Server, tt.expected.Server)
			}
			if cfg.Share != tt.expected.Share {
				t.Errorf("Share = %q, want %q", cfg.Share, tt.expected.Share)
			}
			if cfg.Username != tt.expected.Username {
				t.Errorf("Username = %q, want %q", cfg.Username, tt.expected.Username)
			}
			if cfg.Password != tt.expected.Password {
				t.Errorf("Password = %q, want %q", cfg.Password, tt.expected.Password)
			}
			if cfg.Domain != tt.expected.Domain {
				t.Errorf("Domain = %q, want %q", cfg.Domain, tt.expected.Domain)
			}
			if cfg.Port != tt.expected.Port {
				t.Errorf("Port = %d, want %d", cfg.Port, tt.expected.Port)
			}
			if cfg.GuestAccess != tt.expected.GuestAccess {
				t.Errorf("GuestAccess = %v, want %v", cfg.GuestAccess, tt.expected.GuestAccess)
			}
		})
	}
}
