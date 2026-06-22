package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestRunSlotStopsRetryingAfterTimeout(t *testing.T) {
	cfg := retryTestConfig(t, 150*time.Millisecond, 10*time.Millisecond)
	setLastSummary(runSummary{})
	setRunning("")
	t.Cleanup(func() {
		setLastSummary(runSummary{})
		setRunning("")
	})

	started := time.Now()
	runSlot(context.Background(), cfg, "manual-retry-timeout", true)
	elapsed := time.Since(started)

	minElapsed := cfg.RunTimeout - 20*time.Millisecond
	if elapsed < minElapsed {
		t.Fatalf("runSlot exited before retry timeout: elapsed=%s minimum=%s timeout=%s", elapsed, minElapsed, cfg.RunTimeout)
	}
	if elapsed > time.Second {
		t.Fatalf("runSlot took too long after timeout: elapsed=%s timeout=%s", elapsed, cfg.RunTimeout)
	}
	if got := getRunning(); got != "" {
		t.Fatalf("runSlot must clear the running marker after timeout, got %q", got)
	}
	summary := getLastSummary()
	if summary.Slot != "manual-retry-timeout" {
		t.Fatalf("summary slot = %q, want manual-retry-timeout: %#v", summary.Slot, summary)
	}
	if len(summary.Results) != 1 {
		t.Fatalf("summary result count = %d, want 1: %#v", len(summary.Results), summary.Results)
	}
	record := summary.Results[0]
	if record.AuthID != "codex-retry.json" || record.Status != "failed" {
		t.Fatalf("final retry record = %#v, want failed codex-retry.json", record)
	}
	if record.AttemptCount < 5 {
		t.Fatalf("failed run must keep retrying until timeout, attempt_count=%d want >=5 record=%#v", record.AttemptCount, record)
	}
	if record.LastAttemptAt == "" || record.Error == "" {
		t.Fatalf("failed run must keep last attempt time and error detail: %#v", record)
	}
	persisted, ok := getAttempt(attemptKey("manual-retry-timeout", "codex-retry.json"))
	if !ok || persisted.Status != "failed" {
		t.Fatalf("persisted retry record = %#v ok=%v, want failed", persisted, ok)
	}
}

func TestRunSlotRetriesFailedWarmWithinTimeout(t *testing.T) {
	cfg := retryTestConfig(t, 90*time.Millisecond, 10*time.Millisecond)
	setLastSummary(runSummary{})
	setRunning("")
	t.Cleanup(func() {
		setLastSummary(runSummary{})
		setRunning("")
	})

	runSlot(context.Background(), cfg, "manual-retry-count", true)

	record, ok := getAttempt(attemptKey("manual-retry-count", "codex-retry.json"))
	if !ok {
		t.Fatal("expected retry attempt record to be persisted")
	}
	if record.Status != "failed" {
		t.Fatalf("retry record status = %q, want failed: %#v", record.Status, record)
	}
	if record.AttemptCount <= 1 {
		t.Fatalf("runSlot should retry failed warm before timeout; attempt_count=%d record=%#v", record.AttemptCount, record)
	}
	if summary := getLastSummary(); len(summary.Results) != 1 || summary.Results[0].AttemptCount != record.AttemptCount {
		t.Fatalf("last summary should expose retry count %d, got %#v", record.AttemptCount, summary)
	}
}

func TestPickAuthKeeperMarkerDoesNotFallbackWhenTargetMissing(t *testing.T) {
	raw := mustMarshal(t, schedulerPickRequest{
		Options: schedulerOptions{Headers: map[string][]string{
			defaultMarkerHeader: {"1"},
			defaultTargetHeader: {"codex-target.json"},
		}},
		Candidates: []schedulerCandidate{
			{ID: "codex-other-a.json"},
			{ID: "codex-other-b.json"},
		},
	})

	env := decodeEnvelope(t, pickAuthForTest(t, raw))
	if env.OK {
		var picked schedulerPickResponse
		_ = json.Unmarshal(env.Result, &picked)
		t.Fatalf("keeper marker request must fail closed instead of falling back to another candidate: %#v", picked)
	}
	if env.Error == nil || env.Error.Code != "keeper_target_unavailable" {
		t.Fatalf("expected keeper_target_unavailable fail-closed error, got %#v", env)
	}
}

func retryTestConfig(t *testing.T, runTimeout, retryDelay time.Duration) pluginConfig {
	t.Helper()
	stateDir := t.TempDir()
	if err := loadState(stateDir); err != nil {
		t.Fatal(err)
	}
	authDir := t.TempDir()
	writePhase1AuthFile(t, authDir, "codex-retry.json", `{"priority":10}`)

	cfg := defaultConfig()
	cfg.AuthDir = authDir
	cfg.StateDir = stateDir
	cfg.RunTimeout = runTimeout
	cfg.RetryDelay = retryDelay
	cfg.BetweenAuthDelay = 0
	cfg.DryRun = false
	return cfg
}
