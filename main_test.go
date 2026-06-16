package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestPickAuthRequiresInternalMarker(t *testing.T) {
	raw := mustMarshal(t, schedulerPickRequest{
		Options: schedulerOptions{Headers: map[string][]string{}},
		Candidates: []schedulerCandidate{{
			ID: "codex-a.json",
		}},
	})

	env := decodeEnvelope(t, pickAuthForTest(t, raw))
	if !env.OK {
		t.Fatalf("expected ok envelope, got error %#v", env.Error)
	}
	var picked schedulerPickResponse
	if err := json.Unmarshal(env.Result, &picked); err != nil {
		t.Fatal(err)
	}
	if picked.Handled || picked.AuthID != "" {
		t.Fatalf("unmarked request should not be handled: %#v", picked)
	}
}

func TestPickAuthPinsTargetAuth(t *testing.T) {
	raw := mustMarshal(t, schedulerPickRequest{
		Options: schedulerOptions{Headers: map[string][]string{
			defaultMarkerHeader: {"1"},
			defaultTargetHeader: {"codex-b.json"},
		}},
		Candidates: []schedulerCandidate{
			{ID: "codex-a.json"},
			{ID: "codex-b.json"},
		},
	})

	env := decodeEnvelope(t, pickAuthForTest(t, raw))
	if !env.OK {
		t.Fatalf("expected ok envelope, got error %#v", env.Error)
	}
	var picked schedulerPickResponse
	if err := json.Unmarshal(env.Result, &picked); err != nil {
		t.Fatal(err)
	}
	if !picked.Handled || picked.AuthID != "codex-b.json" {
		t.Fatalf("expected exact target auth, got %#v", picked)
	}
}

func TestPickAuthFailsClosedWhenTargetUnavailable(t *testing.T) {
	raw := mustMarshal(t, schedulerPickRequest{
		Options: schedulerOptions{Headers: map[string][]string{
			defaultMarkerHeader: {"1"},
			defaultTargetHeader: {"codex-missing.json"},
		}},
		Candidates: []schedulerCandidate{{ID: "codex-a.json"}},
	})

	env := decodeEnvelope(t, pickAuthForTest(t, raw))
	if env.OK || env.Error == nil || env.Error.Code != "keeper_target_unavailable" {
		t.Fatalf("expected target unavailable error, got %#v", env)
	}
}

func TestAttemptStateDeduplicatesOnlyAfterSuccess(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	key := attemptKey("2026-06-16 07:00", "codex-a.json")

	failed := attemptRecord{Slot: "2026-06-16 07:00", AuthID: "codex-a.json", Status: "failed", AttemptCount: 1}
	if err := updateAttempt(key, failed); err != nil {
		t.Fatal(err)
	}
	record, ok := getAttempt(key)
	if !ok {
		t.Fatal("expected failed attempt record")
	}
	if isTerminalSuccess(record) {
		t.Fatal("failed attempt must remain retryable")
	}

	sent := attemptRecord{Slot: "2026-06-16 07:00", AuthID: "codex-a.json", Status: "sent", AttemptCount: 2}
	if err := updateAttempt(key, sent); err != nil {
		t.Fatal(err)
	}
	record, ok = getAttempt(key)
	if !ok {
		t.Fatal("expected sent attempt record")
	}
	if !isTerminalSuccess(record) {
		t.Fatal("sent attempt should be terminal success")
	}
}

func TestDailyOffsetTracksLatestSuccessfulSlotToSecond(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	loc := mustLocation("Asia/Shanghai")

	if err := updateAttempt(attemptKey("2026-06-16 07:00", "codex-a.json"), attemptRecord{
		Slot:   "2026-06-16 07:00",
		AuthID: "codex-a.json",
		Status: "sent",
		SentAt: "2026-06-15T23:02:17Z",
	}); err != nil {
		t.Fatal(err)
	}
	nominalNoon := mustParseNominalSlotForTest(t, "2026-06-16 12:00", loc)
	if got := dailyOffsetBeforeSlot("codex-a.json", nominalNoon, cfg, loc); got != 2*time.Minute+17*time.Second {
		t.Fatalf("12:00 offset = %s, want 2m17s", got)
	}

	if err := updateAttempt(attemptKey("2026-06-16 12:00", "codex-a.json"), attemptRecord{
		Slot:   "2026-06-16 12:00",
		AuthID: "codex-a.json",
		Status: "sent",
		SentAt: "2026-06-16T04:03:05Z",
	}); err != nil {
		t.Fatal(err)
	}
	nominalFive := mustParseNominalSlotForTest(t, "2026-06-16 17:00", loc)
	if got := dailyOffsetBeforeSlot("codex-a.json", nominalFive, cfg, loc); got != 3*time.Minute+5*time.Second {
		t.Fatalf("17:00 offset = %s, want 3m5s", got)
	}
}

func TestDailyOffsetResetsAtFirstSlotOfNextDay(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	loc := mustLocation("Asia/Shanghai")

	if err := updateAttempt(attemptKey("2026-06-16 22:00", "codex-a.json"), attemptRecord{
		Slot:   "2026-06-16 22:00",
		AuthID: "codex-a.json",
		Status: "sent",
		SentAt: "2026-06-16T14:04:11Z",
	}); err != nil {
		t.Fatal(err)
	}
	nextMorning := mustParseNominalSlotForTest(t, "2026-06-17 07:00", loc)
	if got := dailyOffsetBeforeSlot("codex-a.json", nextMorning, cfg, loc); got != 0 {
		t.Fatalf("next-day 07:00 offset = %s, want 0", got)
	}
}

func TestIsCodexFileAuth(t *testing.T) {
	if !isCodexFileAuth(authEntry{ID: "1", Name: "codex-user@example.com-team.json", Provider: "codex", Source: "file"}) {
		t.Fatal("expected codex file auth")
	}
	if isCodexFileAuth(authEntry{ID: "1", Name: "codex-user@example.com-team.json", Provider: "codex", RuntimeOnly: true}) {
		t.Fatal("runtime-only auth should be ignored")
	}
	if isCodexFileAuth(authEntry{ID: "1", Name: "sk-codex", Provider: "codex", Source: "memory"}) {
		t.Fatal("memory/API-key auth should be ignored")
	}
}

func TestListCodexAuthsFromDirFallback(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"codex-b@example.com-team.json",
		"codex-a@example.com-plus.json",
		"openai-key.json",
		"codex-not-json.txt",
	} {
		if err := os.WriteFile(dir+"/"+name, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := defaultConfig()
	cfg.AuthDir = dir
	auths, err := listCodexAuthsFromDir(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(auths) != 2 {
		t.Fatalf("auth count = %d, want 2: %#v", len(auths), auths)
	}
	if auths[0].ID != "codex-a@example.com-plus.json" || auths[1].ID != "codex-b@example.com-team.json" {
		t.Fatalf("unexpected sorted auths: %#v", auths)
	}
}

func mustParseNominalSlotForTest(t *testing.T, slot string, loc *time.Location) time.Time {
	t.Helper()
	nominalAt, ok := parseNominalSlot(slot, loc)
	if !ok {
		t.Fatalf("failed to parse nominal slot %q", slot)
	}
	return nominalAt
}

func pickAuthForTest(t *testing.T, raw []byte) []byte {
	t.Helper()
	out, err := pickAuth(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func decodeEnvelope(t *testing.T, raw []byte) envelope {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
