package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsLoginInvalidAuthPhase1Signals(t *testing.T) {
	tests := []struct {
		name          string
		statusMessage string
		want          bool
	}{
		{
			name:          "unauthorized string",
			statusMessage: "unauthorized",
			want:          true,
		},
		{
			name:          "authentication_error type",
			statusMessage: `{"error":{"type":"authentication_error"}}`,
			want:          true,
		},
		{
			name:          "unauthorized code",
			statusMessage: `{"error":{"code":"unauthorized"}}`,
			want:          true,
		},
		{
			name:          "no_credentials code",
			statusMessage: `{"error":{"code":"no_credentials"}}`,
			want:          true,
		},
		{
			name:          "invalid_credential code",
			statusMessage: `{"error":{"code":"invalid_credential"}}`,
			want:          true,
		},
		{
			name:          "quota exhausted",
			statusMessage: "quota exhausted",
			want:          false,
		},
		{
			name:          "usage_limit_reached type",
			statusMessage: `{"error":{"type":"usage_limit_reached"}}`,
			want:          false,
		},
		{
			name:          "unknown error",
			statusMessage: `{"error":{"type":"server_error","code":"unknown"}}`,
			want:          false,
		},
		{
			name:          "auth_unavailable code alone",
			statusMessage: `{"error":{"code":"auth_unavailable"}}`,
			want:          false,
		},
		{
			name:          "revoked generic text",
			statusMessage: "token revoked",
			want:          false,
		},
		{
			name:          "login required generic text",
			statusMessage: "login required",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLoginInvalidAuth(authEntry{StatusMessage: tt.statusMessage})
			if got != tt.want {
				t.Fatalf("isLoginInvalidAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWarmableCodexAuthsIncludesUnavailableUsageLimited(t *testing.T) {
	auths := warmableCodexAuths([]authEntry{
		phase1CodexAuth("codex-usage-limited.json", func(entry *authEntry) {
			entry.Unavailable = true
			entry.StatusMessage = `{"error":{"type":"usage_limit_reached"}}`
		}),
	})

	if len(auths) != 1 || auths[0].ID != "codex-usage-limited.json" {
		t.Fatalf("warmable auths = %#v, want usage-limited unavailable auth included", auths)
	}
}

func TestWarmableCodexAuthsIncludesQuotaExhausted(t *testing.T) {
	auths := warmableCodexAuths([]authEntry{
		phase1CodexAuth("codex-quota.json", func(entry *authEntry) {
			entry.Unavailable = true
			entry.StatusMessage = "quota exhausted"
		}),
	})

	if len(auths) != 1 || auths[0].ID != "codex-quota.json" {
		t.Fatalf("warmable auths = %#v, want quota-exhausted auth included", auths)
	}
}

func TestWarmableCodexAuthsExcludesDisabled(t *testing.T) {
	auths := warmableCodexAuths([]authEntry{
		phase1CodexAuth("codex-disabled.json", func(entry *authEntry) {
			entry.Disabled = true
		}),
	})

	if len(auths) != 0 {
		t.Fatalf("warmable auths = %#v, want disabled auth excluded", auths)
	}
}

func TestWarmableCodexAuthsExcludesLoginInvalid(t *testing.T) {
	auths := warmableCodexAuths([]authEntry{
		phase1CodexAuth("codex-invalid.json", func(entry *authEntry) {
			entry.StatusMessage = "unauthorized"
		}),
	})

	if len(auths) != 0 {
		t.Fatalf("warmable auths = %#v, want login-invalid auth excluded", auths)
	}
}

func TestManagedCodexAuthsStillSkipRuntimeOnlyMemoryOnlyNonCodex(t *testing.T) {
	auths := managedCodexAuths([]authEntry{
		phase1CodexAuth("codex-good.json", nil),
		phase1CodexAuth("codex-runtime.json", func(entry *authEntry) {
			entry.RuntimeOnly = true
		}),
		phase1CodexAuth("codex-memory.json", func(entry *authEntry) {
			entry.Source = "memory"
			entry.Path = ""
		}),
		phase1CodexAuth("codex-noncodex.json", func(entry *authEntry) {
			entry.Provider = "openai"
		}),
	})

	if len(auths) != 1 || auths[0].ID != "codex-good.json" {
		t.Fatalf("managed auths = %#v, want only file-based Codex auth", auths)
	}
}

func TestCountDisplayCodexCredentialsUsesWarmableCodexAuths(t *testing.T) {
	got := countDisplayCodexCredentials([]authEntry{
		phase1CodexAuth("codex-usage-limited.json", func(entry *authEntry) {
			entry.Unavailable = true
			entry.StatusMessage = `{"error":{"type":"usage_limit_reached"}}`
		}),
		phase1CodexAuth("codex-quota.json", func(entry *authEntry) {
			entry.StatusMessage = "quota exhausted"
		}),
		phase1CodexAuth("codex-unauthorized.json", func(entry *authEntry) {
			entry.StatusMessage = "unauthorized"
		}),
		phase1CodexAuth("codex-disabled.json", func(entry *authEntry) {
			entry.Disabled = true
		}),
	})

	if got != 2 {
		t.Fatalf("countDisplayCodexCredentials() = %d, want 2", got)
	}
}

func TestNormalizeAuthEntriesProductionPathIncludesUnavailableUsageLimited(t *testing.T) {
	cfg := defaultConfig()
	cfg.IncludeUnavailableAuths = false

	auths := normalizeAuthEntries([]authEntry{
		phase1CodexAuth("codex-usage-limited.json", func(entry *authEntry) {
			entry.Unavailable = true
			entry.StatusMessage = `{"error":{"type":"usage_limit_reached"}}`
		}),
		phase1CodexAuth("codex-quota.json", func(entry *authEntry) {
			entry.Unavailable = true
			entry.StatusMessage = "quota exhausted"
		}),
		phase1CodexAuth("codex-invalid.json", func(entry *authEntry) {
			entry.Unavailable = true
			entry.StatusMessage = "unauthorized"
		}),
		phase1CodexAuth("codex-disabled.json", func(entry *authEntry) {
			entry.Disabled = true
		}),
	}, cfg)

	if got := phase1AuthIDs(auths); strings.Join(got, ",") != "codex-quota.json,codex-usage-limited.json" {
		t.Fatalf("normalizeAuthEntries() IDs = %v, want unavailable usage/quota auths only", got)
	}
}

func TestListCodexAuthsFromDirProductionPathIncludesUnavailableUsageLimited(t *testing.T) {
	dir := t.TempDir()
	writePhase1AuthFile(t, dir, "codex-usage-limited.json", `{"unavailable":true,"status_message":"{\"error\":{\"type\":\"usage_limit_reached\"}}"}`)
	writePhase1AuthFile(t, dir, "codex-invalid.json", `{"unavailable":true,"status_message":"unauthorized"}`)
	writePhase1AuthFile(t, dir, "codex-disabled.json", `{"disabled":true}`)

	cfg := defaultConfig()
	cfg.AuthDir = dir
	cfg.IncludeUnavailableAuths = false
	auths, err := listCodexAuthsFromDir(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if got := phase1AuthIDs(auths); strings.Join(got, ",") != "codex-usage-limited.json" {
		t.Fatalf("listCodexAuthsFromDir() IDs = %v, want unavailable usage-limited auth included and invalid/disabled excluded", got)
	}
}

func TestRenderStatusPageCountsDisplayCredentialsFromRawEntries(t *testing.T) {
	cfgMu.Lock()
	previousCfg := activeCfg
	activeCfg = defaultConfig()
	cfgMu.Unlock()
	t.Cleanup(func() {
		cfgMu.Lock()
		activeCfg = previousCfg
		cfgMu.Unlock()
	})
	t.Cleanup(func() { setRunning("") })
	setRunning("")
	setLastSummary(runSummary{})
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	page := string(renderStatusPageWithAuthLister(func(context.Context, pluginConfig) ([]authEntry, error) {
		return []authEntry{
			phase1CodexAuth("codex-usage-limited.json", func(entry *authEntry) {
				entry.Unavailable = true
				entry.StatusMessage = `{"error":{"type":"usage_limit_reached"}}`
			}),
			phase1CodexAuth("codex-quota.json", func(entry *authEntry) {
				entry.StatusMessage = "quota exhausted"
			}),
			phase1CodexAuth("codex-invalid.json", func(entry *authEntry) {
				entry.StatusMessage = "unauthorized"
			}),
			phase1CodexAuth("codex-disabled.json", func(entry *authEntry) {
				entry.Disabled = true
			}),
		}, nil
	}))

	if !strings.Contains(page, `Codex credentials</span><span class="v">2</span>`) {
		t.Fatalf("status page must render display credential count 2 via countDisplayCodexCredentials; page:\n%s", page)
	}
}

func TestRenderStatusPageShowsAuthListError(t *testing.T) {
	page := string(renderStatusPageWithAuthLister(func(context.Context, pluginConfig) ([]authEntry, error) {
		return nil, errors.New("auth list failed")
	}))
	if !strings.Contains(page, `<span class="badge bad">error</span>`) || !strings.Contains(page, "auth list failed") {
		t.Fatalf("status page must preserve auth-list error behavior; page:\n%s", page)
	}
}

func phase1AuthIDs(auths []authEntry) []string {
	ids := make([]string, 0, len(auths))
	for _, auth := range auths {
		ids = append(ids, auth.ID)
	}
	return ids
}

func writePhase1AuthFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func phase1CodexAuth(name string, mutate func(*authEntry)) authEntry {
	entry := authEntry{
		ID:       name,
		Name:     name,
		Provider: "codex",
		Source:   "file",
		Path:     "/auths/" + name,
	}
	if mutate != nil {
		mutate(&entry)
	}
	return entry
}
