package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunSlotPersistsNoAuthsDiagnostic(t *testing.T) {
	stateDir := t.TempDir()
	if err := loadState(stateDir); err != nil {
		t.Fatal(err)
	}
	setLastSummary(runSummary{})
	t.Cleanup(func() { setLastSummary(runSummary{}) })

	cfg := defaultConfig()
	cfg.AuthDir = t.TempDir()
	runSlot(context.Background(), cfg, "manual-empty", true)

	summary := getLastSummary()
	if summary.Slot != "manual-empty" {
		t.Fatalf("summary slot = %q, want manual-empty: %#v", summary.Slot, summary)
	}
	if len(summary.Results) != 1 {
		t.Fatalf("summary result count = %d, want 1: %#v", len(summary.Results), summary.Results)
	}
	record := summary.Results[0]
	if record.Status != "no_auths" {
		t.Fatalf("diagnostic status = %q, want no_auths: %#v", record.Status, record)
	}
	if !strings.Contains(record.Error, "no enabled file-based Codex OAuth") {
		t.Fatalf("diagnostic detail should explain no auths, got %q", record.Error)
	}
	persisted, ok := getAttempt(runDiagnosticAttemptKey("manual-empty"))
	if !ok {
		t.Fatal("expected no_auths diagnostic to be persisted as a sentinel attempt")
	}
	if persisted.Status != "no_auths" {
		t.Fatalf("persisted diagnostic status = %q, want no_auths: %#v", persisted.Status, persisted)
	}
}

func TestRunSlotPersistsNoWarmableDiagnosticForLoginInvalidAuths(t *testing.T) {
	stateDir := t.TempDir()
	if err := loadState(stateDir); err != nil {
		t.Fatal(err)
	}
	setLastSummary(runSummary{})
	setRunning("")
	defer setLastSummary(runSummary{})
	defer setRunning("")

	authDir := t.TempDir()
	writePhase1AuthFile(t, authDir, "codex-unauthorized.json", `{"status_message":"unauthorized"}`)
	writePhase1AuthFile(t, authDir, "codex-auth-error.json", `{"status_message":"{\"error\":{\"type\":\"authentication_error\"}}"}`)

	cfg := defaultConfig()
	cfg.AuthDir = authDir
	cfg.StateDir = stateDir
	runSlot(context.Background(), cfg, "manual-invalid", true)

	summary := getLastSummary()
	if summary.Slot != "manual-invalid" {
		t.Fatalf("summary slot = %q, want manual-invalid: %#v", summary.Slot, summary)
	}
	if hasStatus(summary.Results, "no_auths") {
		t.Fatalf("login-invalid managed Codex OAuths must not be reported as no_auths: %#v", summary.Results)
	}
	if !hasStatus(summary.Results, "no_warmable_auths") {
		t.Fatalf("summary should include no_warmable_auths diagnostic: %#v", summary.Results)
	}
	if got := countStatus(summary.Results, "auth_invalid"); got != 2 {
		t.Fatalf("auth_invalid result count = %d, want 2: %#v", got, summary.Results)
	}
	if _, ok := getAttempt(runDiagnosticAttemptKey("manual-invalid")); !ok {
		t.Fatal("expected no_warmable_auths diagnostic to be persisted as a sentinel attempt")
	}
	if persisted, ok := getAttempt(attemptKey("manual-invalid", "codex-unauthorized.json")); !ok || persisted.Status != "auth_invalid" {
		t.Fatalf("expected unauthorized auth_invalid diagnostic to persist, got ok=%v record=%#v", ok, persisted)
	}

	setLastSummary(runSummary{})
	if err := loadState(stateDir); err != nil {
		t.Fatal(err)
	}
	restored := lastPersistedSummary()
	if restored.Slot != "manual-invalid" {
		t.Fatalf("restored summary slot = %q, want manual-invalid: %#v", restored.Slot, restored)
	}
	if hasStatus(restored.Results, "no_auths") || !hasStatus(restored.Results, "no_warmable_auths") || countStatus(restored.Results, "auth_invalid") != 2 {
		t.Fatalf("restored diagnostic summary mismatch: %#v", restored.Results)
	}

	withActiveConfig(t, cfg)
	page := string(renderStatusPage())
	if strings.Contains(page, "no_auths") {
		t.Fatalf("status page must not show no_auths for login-invalid managed OAuths; page:\n%s", page)
	}
	if !strings.Contains(page, "no_warmable_auths") && !strings.Contains(page, "auth_invalid") {
		t.Fatalf("status page should show no_warmable_auths or auth_invalid; page:\n%s", page)
	}
}

func TestLastPersistedSummaryRestoresDiagnosticRun(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := updateAttempt(runDiagnosticAttemptKey("manual-empty"), runDiagnosticRecord(
		"manual-empty",
		"2026-06-22T01:02:03Z",
		"no_auths",
		"no enabled file-based Codex OAuth credentials found",
	)); err != nil {
		t.Fatal(err)
	}

	summary := lastPersistedSummary()
	if summary.Slot != "manual-empty" || summary.StartedAt != "2026-06-22T01:02:03Z" {
		t.Fatalf("summary did not restore diagnostic run metadata: %#v", summary)
	}
	if len(summary.Results) != 1 || summary.Results[0].Status != "no_auths" {
		t.Fatalf("summary did not restore diagnostic result: %#v", summary.Results)
	}
}

func TestRenderStatusPageCompletedEmptyRunDoesNotShowStarting(t *testing.T) {
	cfg := defaultConfig()
	cfg.AuthDir = t.TempDir()
	cfg.StateDir = t.TempDir()
	withActiveConfig(t, cfg)
	if err := loadState(cfg.StateDir); err != nil {
		t.Fatal(err)
	}
	setRunning("")
	setLastSummary(runSummary{})
	t.Cleanup(func() {
		setRunning("")
		setLastSummary(runSummary{})
	})
	if err := updateAttempt(runDiagnosticAttemptKey("manual-empty"), runDiagnosticRecord(
		"manual-empty",
		"2026-06-22T01:02:03Z",
		"no_auths",
		"no enabled file-based Codex OAuth credentials found",
	)); err != nil {
		t.Fatal(err)
	}

	page := string(renderStatusPage())
	if strings.Contains(page, "Starting&hellip;") {
		t.Fatalf("completed empty run must not render Starting; page:\n%s", page)
	}
	if !strings.Contains(page, "no_auths") {
		t.Fatalf("completed empty run should render no_auths diagnostic; page:\n%s", page)
	}
	if !strings.Contains(page, `Attempts recorded</span><span class="v">0`) {
		t.Fatalf("diagnostic sentinel must not be counted as a recorded warm attempt; page:\n%s", page)
	}
	if !strings.Contains(page, `<td>0</td><td class="mono">—</td><td class="err">no enabled file-based Codex OAuth credentials found`) {
		t.Fatalf("diagnostic sentinel should render an em dash in the Next run column; page:\n%s", page)
	}
}

func TestRenderStatusPageRunningEmptyRunShowsPreparing(t *testing.T) {
	cfg := defaultConfig()
	cfg.AuthDir = t.TempDir()
	cfg.StateDir = t.TempDir()
	withActiveConfig(t, cfg)
	if err := loadState(cfg.StateDir); err != nil {
		t.Fatal(err)
	}
	setLastSummary(runSummary{})
	setRunning("manual-empty")
	t.Cleanup(func() {
		setRunning("")
		setLastSummary(runSummary{})
	})

	page := string(renderStatusPage())
	if strings.Contains(page, "Starting") || strings.Contains(page, "Starting&hellip;") {
		t.Fatalf("running empty run should not render Starting; page:\n%s", page)
	}
	if !strings.Contains(page, "Preparing&hellip;") {
		t.Fatalf("running empty run should render Preparing; page:\n%s", page)
	}
}

func TestRunDiagnosticHelperIdentifiesOnlySentinelRecords(t *testing.T) {
	record := runDiagnosticRecord("manual-empty", "2026-06-22T01:02:03Z", "no_auths", "no enabled file-based Codex OAuth credentials found")
	if record.AuthID != runDiagnosticAuthID {
		t.Fatalf("diagnostic auth ID = %q, want sentinel %q", record.AuthID, runDiagnosticAuthID)
	}
	if !isRunDiagnosticRecord(record) {
		t.Fatalf("expected runDiagnosticRecord to be recognized as diagnostic: %#v", record)
	}
	if got, want := runDiagnosticAttemptKey("manual-empty"), attemptKey("manual-empty", runDiagnosticAuthID); got != want {
		t.Fatalf("diagnostic key = %q, want %q", got, want)
	}
	collidingRealAttempt := record
	collidingRealAttempt.AuthName = "codex-real.json"
	collidingRealAttempt.AttemptCount = 1
	if isRunDiagnosticRecord(collidingRealAttempt) {
		t.Fatalf("record with sentinel-like auth ID but non-diagnostic name must not be treated as diagnostic: %#v", collidingRealAttempt)
	}
}

func TestDiagnosticSentinelDoesNotRenderNextRun(t *testing.T) {
	cfg := defaultConfig()
	loc := mustLocation(cfg.Timezone)
	now := time.Date(2026, 6, 22, 8, 0, 0, 0, loc)
	diagnostic := runDiagnosticRecord("manual-empty", "2026-06-22T01:02:03Z", "no_auths", "no enabled file-based Codex OAuth credentials found")
	if got := nextRunDisplayForRecord(now, diagnostic, cfg, loc); got != "—" {
		t.Fatalf("diagnostic next run display = %q, want em dash", got)
	}
	real := attemptRecord{Slot: "2026-06-22 07:00", AuthID: "codex-a.json", AuthName: "codex-a.json", Status: "sent"}
	if got := nextRunDisplayForRecord(now, real, cfg, loc); got == "—" {
		t.Fatalf("real auth should still render a scheduled next run, got %q", got)
	}
}

func TestAttemptsRecordedExcludesDiagnostics(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := updateAttempt(runDiagnosticAttemptKey("manual-empty"), runDiagnosticRecord(
		"manual-empty",
		"2026-06-22T01:02:03Z",
		"no_auths",
		"no enabled file-based Codex OAuth credentials found",
	)); err != nil {
		t.Fatal(err)
	}
	if got := recordedWarmAttemptCount(); got != 0 {
		t.Fatalf("diagnostic-only attempt count = %d, want 0", got)
	}
	if err := updateAttempt(attemptKey("2026-06-22 07:00", "codex-a.json"), attemptRecord{
		Slot:         "2026-06-22 07:00",
		AuthID:       "codex-a.json",
		AuthName:     "codex-a.json",
		Status:       "sent",
		AttemptCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := recordedWarmAttemptCount(); got != 1 {
		t.Fatalf("warm attempt count with one real attempt and one diagnostic = %d, want 1", got)
	}
}

func TestRunSlotClearsStaleRunDiagnosticWhenWarmableAuthsExist(t *testing.T) {
	for _, staleStatus := range []string{"no_auths", "no_warmable_auths"} {
		t.Run(staleStatus, func(t *testing.T) {
			stateDir := t.TempDir()
			if err := loadState(stateDir); err != nil {
				t.Fatal(err)
			}
			setLastSummary(runSummary{})
			setRunning("")
			t.Cleanup(func() {
				setLastSummary(runSummary{})
				setRunning("")
			})

			slot := "manual-reused-" + staleStatus
			if err := updateAttempt(runDiagnosticAttemptKey(slot), runDiagnosticRecord(
				slot,
				"2026-06-22T01:02:03Z",
				staleStatus,
				"stale whole-run diagnostic",
			)); err != nil {
				t.Fatal(err)
			}

			authDir := t.TempDir()
			writePhase1AuthFile(t, authDir, "codex-invalid.json", `{"status_message":"unauthorized"}`)
			writePhase1AuthFile(t, authDir, "codex-warmable.json", `{"priority":10}`)
			cfg := defaultConfig()
			cfg.AuthDir = authDir
			cfg.StateDir = stateDir
			cfg.DryRun = true
			cfg.BetweenAuthDelay = 0

			runSlot(context.Background(), cfg, slot, true)

			summary := getLastSummary()
			if hasStatus(summary.Results, "no_auths") || hasStatus(summary.Results, "no_warmable_auths") {
				t.Fatalf("summary must not expose stale whole-run diagnostic after a real warm attempt: %#v", summary.Results)
			}
			if !hasStatus(summary.Results, "dry_run") {
				t.Fatalf("summary should include the warmable auth dry-run attempt: %#v", summary.Results)
			}
			if !hasStatus(summary.Results, "auth_invalid") {
				t.Fatalf("per-auth auth_invalid diagnostic should be preserved: %#v", summary.Results)
			}
			if _, ok := getAttempt(runDiagnosticAttemptKey(slot)); ok {
				t.Fatalf("stale whole-run diagnostic sentinel should be removed from state for slot %q", slot)
			}
			live := attemptsForSlot(slot)
			if hasStatus(live, "no_auths") || hasStatus(live, "no_warmable_auths") || !hasStatus(live, "dry_run") || !hasStatus(live, "auth_invalid") {
				t.Fatalf("live slot attempts should suppress stale whole-run diagnostics and keep real/per-auth records: %#v", live)
			}

			setLastSummary(runSummary{})
			restored := lastPersistedSummary()
			if hasStatus(restored.Results, "no_auths") || hasStatus(restored.Results, "no_warmable_auths") || !hasStatus(restored.Results, "dry_run") || !hasStatus(restored.Results, "auth_invalid") {
				t.Fatalf("restored summary should suppress stale whole-run diagnostics and keep real/per-auth records: %#v", restored.Results)
			}
		})
	}
}

func hasStatus(records []attemptRecord, status string) bool {
	return countStatus(records, status) > 0
}

func countStatus(records []attemptRecord, status string) int {
	count := 0
	for _, record := range records {
		if record.Status == status {
			count++
		}
	}
	return count
}

func withActiveConfig(t *testing.T, cfg pluginConfig) {
	t.Helper()
	cfgMu.Lock()
	previous := activeCfg
	activeCfg = cfg
	cfgMu.Unlock()
	t.Cleanup(func() {
		cfgMu.Lock()
		activeCfg = previous
		cfgMu.Unlock()
	})
}
