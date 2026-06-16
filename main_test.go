package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestKeepaliveBodyInputIsListWithoutMetadata(t *testing.T) {
	cfg := defaultConfig()
	cfg.Prompt = "hi"
	body, err := keepaliveBody(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The codex exit protocol requires `input` as a list and rejects a
	// `metadata` field ("Unsupported parameter: metadata").
	var decoded struct {
		Input []struct {
			Type    string `json:"type"`
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"input"`
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("keepalive body is not valid json: %v (%s)", err, body)
	}
	if decoded.Metadata != nil {
		t.Fatalf("keepalive body must not send metadata: %s", body)
	}
	if len(decoded.Input) != 1 {
		t.Fatalf("input must be a non-empty list, got %d: %s", len(decoded.Input), body)
	}
	item := decoded.Input[0]
	if item.Type != "message" || item.Role != "user" || len(item.Content) != 1 {
		t.Fatalf("unexpected input item shape: %s", body)
	}
	if item.Content[0].Type != "input_text" || item.Content[0].Text != "hi" {
		t.Fatalf("unexpected input content: %s", body)
	}
}

func TestBuildSetPriorityRequest(t *testing.T) {
	cfg := defaultConfig()
	cfg.ManagementBaseURL = "https://127.0.0.1:8317"
	cfg.ManagementKey = "secret-key"
	req, err := buildSetPriorityRequest(context.Background(), cfg, "codex-x.json", 10)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodPatch {
		t.Fatalf("method = %s, want PATCH", req.Method)
	}
	if got := req.URL.String(); got != "https://127.0.0.1:8317/v0/management/auth-files/fields" {
		t.Fatalf("url = %s", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer secret-key" {
		t.Fatalf("authorization = %q", got)
	}
	body, _ := io.ReadAll(req.Body)
	var decoded struct {
		Name     string `json:"name"`
		Priority int    `json:"priority"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body not json: %v (%s)", err, body)
	}
	if decoded.Name != "codex-x.json" || decoded.Priority != 10 {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestBumpStateRoundTrip(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if len(pendingBumps()) != 0 {
		t.Fatal("expected no pending bumps initially")
	}
	if _, err := recordBump("codex-a.json", 8); err != nil {
		t.Fatal(err)
	}
	if got := pendingBumps()["codex-a.json"]; got != 8 {
		t.Fatalf("recorded bump = %d, want 8", got)
	}
	if err := clearBump("codex-a.json"); err != nil {
		t.Fatal(err)
	}
	if len(pendingBumps()) != 0 {
		t.Fatal("expected no pending bumps after clear")
	}
}

func TestWarmAuthLowPriorityRequiresManagementKey(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.ManagementKey = ""
	cfg.BumpPriority = 10
	auth := authEntry{ID: "codex-low.json", Name: "codex-low.json", Priority: 8}
	err := warmAuth(context.Background(), cfg, "2026-06-16 07:00", auth, 9)
	if err == nil || !strings.Contains(err.Error(), "management_key") {
		t.Fatalf("expected management_key error, got %v", err)
	}
	if len(pendingBumps()) != 0 {
		t.Fatal("must not record a bump when management_key is missing")
	}
}

func TestWarmAuthTopTierDoesNotBump(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.BumpPriority = 10
	auth := authEntry{ID: "codex-top.json", Name: "codex-top.json", Priority: 10}
	// No host is wired in unit tests, so the underlying send fails — the point is
	// that a top-tier auth is warmed directly and never recorded as a bump.
	if err := warmAuth(context.Background(), cfg, "2026-06-16 07:00", auth, 10); err == nil {
		t.Fatal("expected an error from the direct send (no host wired), got nil")
	}
	if len(pendingBumps()) != 0 {
		t.Fatalf("top-tier auth must not be bumped, got %#v", pendingBumps())
	}
}

func TestListCodexAuthsFromDirReadsPriority(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/codex-p@example.com-team.json", []byte(`{"priority":8,"disabled":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.AuthDir = dir
	auths, err := listCodexAuthsFromDir(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(auths) != 1 || auths[0].Priority != 8 {
		t.Fatalf("expected priority 8 read from file, got %#v", auths)
	}
}

// mgmtRecorder is a test double for the CLIProxyAPI management API.
type mgmtRecorder struct {
	mu     sync.Mutex
	method string
	path   string
	auth   string
	body   []byte
	calls  int
	status int // response status to send (0 -> 200)
}

func (rr *mgmtRecorder) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rr.mu.Lock()
	rr.method, rr.path, rr.auth, rr.body = r.Method, r.URL.Path, r.Header.Get("Authorization"), body
	rr.calls++
	status := rr.status
	rr.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if status == http.StatusOK {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	} else {
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}
}

func writeServerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath
}

func TestSetAuthPriorityViaServer(t *testing.T) {
	rr := &mgmtRecorder{}
	srv := httptest.NewTLSServer(http.HandlerFunc(rr.handler))
	defer srv.Close()
	cfg := defaultConfig()
	cfg.ManagementBaseURL = srv.URL
	cfg.ManagementKey = "k"
	cfg.ManagementCACert = writeServerCA(t, srv)
	if err := setAuthPriority(context.Background(), cfg, "codex-a.json", 10); err != nil {
		t.Fatal(err)
	}
	rr.mu.Lock()
	defer rr.mu.Unlock()
	if rr.method != http.MethodPatch || rr.path != managementAuthFieldsPath || rr.auth != "Bearer k" {
		t.Fatalf("unexpected request: %s %s auth=%q", rr.method, rr.path, rr.auth)
	}
	var decoded struct {
		Name     string `json:"name"`
		Priority int    `json:"priority"`
	}
	if err := json.Unmarshal(rr.body, &decoded); err != nil {
		t.Fatalf("body not json: %v (%s)", err, rr.body)
	}
	if decoded.Name != "codex-a.json" || decoded.Priority != 10 {
		t.Fatalf("unexpected body: %s", rr.body)
	}
}

func TestSetAuthPriorityNon200Errors(t *testing.T) {
	rr := &mgmtRecorder{status: http.StatusForbidden}
	srv := httptest.NewTLSServer(http.HandlerFunc(rr.handler))
	defer srv.Close()
	cfg := defaultConfig()
	cfg.ManagementBaseURL = srv.URL
	cfg.ManagementKey = "k"
	cfg.ManagementCACert = writeServerCA(t, srv)
	if err := setAuthPriority(context.Background(), cfg, "codex-a.json", 10); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected error mentioning status 403, got %v", err)
	}
}

func TestReconcileBumpsRestoresAndClears(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	rr := &mgmtRecorder{}
	srv := httptest.NewTLSServer(http.HandlerFunc(rr.handler))
	defer srv.Close()
	if _, err := recordBump("codex-a.json", 8); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.ManagementBaseURL = srv.URL
	cfg.ManagementKey = "k"
	cfg.ManagementCACert = writeServerCA(t, srv)
	reconcileBumps(context.Background(), cfg)
	rr.mu.Lock()
	calls := rr.calls
	body := rr.body
	rr.mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected 1 restore PATCH, got %d", calls)
	}
	var decoded struct {
		Priority int `json:"priority"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("restore body not json: %v (%s)", err, body)
	}
	if decoded.Priority != 8 {
		t.Fatalf("restored priority = %d, want 8", decoded.Priority)
	}
	if len(pendingBumps()) != 0 {
		t.Fatal("bump must be cleared after a successful restore")
	}
}

func TestWarmAuthRaiseFailureKeepsBumpRecord(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	rr := &mgmtRecorder{status: http.StatusInternalServerError}
	srv := httptest.NewTLSServer(http.HandlerFunc(rr.handler))
	defer srv.Close()
	cfg := defaultConfig()
	cfg.ManagementBaseURL = srv.URL
	cfg.ManagementKey = "k"
	cfg.ManagementCACert = writeServerCA(t, srv)
	cfg.BumpPriority = 10
	auth := authEntry{ID: "codex-low.json", Name: "codex-low.json", Priority: 8}
	err := warmAuth(context.Background(), cfg, "2026-06-16 07:00", auth, 9)
	if err == nil || !strings.Contains(err.Error(), "raise priority") {
		t.Fatalf("expected raise-priority error, got %v", err)
	}
	// A failed raise must keep the bump record so reconcileBumps can recover it.
	if _, ok := pendingBumps()["codex-low.json"]; !ok {
		t.Fatal("bump record must be retained after a failed raise")
	}
	// And it must still attempt an inline revert (raise + revert == 2 calls).
	rr.mu.Lock()
	calls := rr.calls
	rr.mu.Unlock()
	if calls != 2 {
		t.Fatalf("expected raise + inline revert attempt (2 calls), got %d", calls)
	}
}

func TestConfigureNoOpWhenUnchanged(t *testing.T) {
	cfgMu.Lock()
	configuredOnce = false
	activeCfg = defaultConfig()
	cfgMu.Unlock()
	// configure() starts reconcileLoop (which runs even while disabled); cancel
	// it when the test ends. Registered separately from the global-reset cleanup
	// below because stopLoop takes cfgMu, which that cleanup already holds.
	t.Cleanup(stopLoop)
	t.Cleanup(func() {
		cfgMu.Lock()
		configuredOnce = false
		activeCfg = defaultConfig()
		cfgMu.Unlock()
	})
	dir := t.TempDir()
	raw := mustMarshal(t, lifecycleRequest{ConfigYAML: []byte("enabled: false\nstate_dir: \"" + dir + "\"\n")})
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	stateMu.Lock()
	first := statePath
	statePath = "SENTINEL"
	stateMu.Unlock()
	if first == "" {
		t.Fatal("first configure should set statePath via loadState")
	}
	// An identical reconfigure (e.g. one the host fires after an auth-file write)
	// must be a no-op: it must not re-run loadState, so the sentinel survives.
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	stateMu.Lock()
	afterNoop := statePath
	stateMu.Unlock()
	if afterNoop != "SENTINEL" {
		t.Fatalf("identical reconfigure must be a no-op; statePath = %q, want SENTINEL", afterNoop)
	}
	// A changed config must apply (re-run loadState, overwriting the sentinel).
	raw2 := mustMarshal(t, lifecycleRequest{ConfigYAML: []byte("enabled: false\nmodel: \"gpt-5.5\"\nstate_dir: \"" + dir + "\"\n")})
	if err := configure(raw2); err != nil {
		t.Fatal(err)
	}
	stateMu.Lock()
	afterChange := statePath
	stateMu.Unlock()
	if afterChange == "SENTINEL" {
		t.Fatal("a changed config must apply (loadState should overwrite statePath)")
	}
}

func TestWarmAuthRestoresAfterFailedSend(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	rr := &mgmtRecorder{} // 200 OK for both raise and restore
	srv := httptest.NewTLSServer(http.HandlerFunc(rr.handler))
	defer srv.Close()
	cfg := defaultConfig()
	cfg.ManagementBaseURL = srv.URL
	cfg.ManagementKey = "k"
	cfg.ManagementCACert = writeServerCA(t, srv)
	cfg.BumpPriority = 10
	auth := authEntry{ID: "codex-low.json", Name: "codex-low.json", Priority: 8}
	// The raise succeeds; the warm (sendHi) fails because no host is wired. The
	// deferred restore must still run and clear the bump record.
	if err := warmAuth(context.Background(), cfg, "2026-06-16 07:00", auth, 9); err == nil {
		t.Fatal("expected a send error (no host wired)")
	}
	if len(pendingBumps()) != 0 {
		t.Fatalf("deferred restore must clear the bump even when the warm fails; got %#v", pendingBumps())
	}
	rr.mu.Lock()
	calls, body := rr.calls, rr.body
	rr.mu.Unlock()
	if calls != 2 {
		t.Fatalf("expected raise + restore (2 calls), got %d", calls)
	}
	var decoded struct {
		Priority int `json:"priority"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("restore body not json: %v (%s)", err, body)
	}
	if decoded.Priority != 8 {
		t.Fatalf("final restore priority = %d, want 8 (original)", decoded.Priority)
	}
}

func TestRecordBumpFirstWriteWins(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if got, err := recordBump("codex-x.json", 8); err != nil {
		t.Fatal(err)
	} else if got != 8 {
		t.Fatalf("first recordBump should return the recorded original; got %d, want 8", got)
	}
	// A second record (e.g. a re-bump after a prior restore failed and left the
	// entry) must NOT overwrite the true original (8) with the already-raised
	// value (10), and must RETURN 8 so the caller restores to the true original.
	got, err := recordBump("codex-x.json", 10)
	if err != nil {
		t.Fatal(err)
	}
	if got != 8 {
		t.Fatalf("recordBump must return the first (true original) priority; got %d, want 8", got)
	}
	if p := pendingBumps()["codex-x.json"]; p != 8 {
		t.Fatalf("stored bump must stay at the true original; got %d, want 8", p)
	}
}

func TestWarmAuthRestoresToRecordedOriginalWhenListIsStale(t *testing.T) {
	if err := loadState(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	// Simulate a prior failed restore: the true original (8) is already recorded,
	// while the run-start auth list now reports the auth at its stale, already-
	// raised value (9). The restore must target the recorded original, not 9.
	if _, err := recordBump("codex-low.json", 8); err != nil {
		t.Fatal(err)
	}
	rr := &mgmtRecorder{} // 200 OK for raise and restore
	srv := httptest.NewTLSServer(http.HandlerFunc(rr.handler))
	defer srv.Close()
	cfg := defaultConfig()
	cfg.ManagementBaseURL = srv.URL
	cfg.ManagementKey = "k"
	cfg.ManagementCACert = writeServerCA(t, srv)
	cfg.BumpPriority = 10
	auth := authEntry{ID: "codex-low.json", Name: "codex-low.json", Priority: 9} // stale list value
	// Below the top tier (10), so it is re-bumped; the warm fails (no host), but
	// the deferred restore still runs and must use the recorded original (8).
	_ = warmAuth(context.Background(), cfg, "2026-06-16 07:00", auth, 10)
	rr.mu.Lock()
	body := rr.body
	rr.mu.Unlock()
	var decoded struct {
		Priority int `json:"priority"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("restore body not json: %v (%s)", err, body)
	}
	if decoded.Priority != 8 {
		t.Fatalf("restore must use recorded original 8, not stale list value 9; got %d", decoded.Priority)
	}
}

func TestClearRunningOnlyClearsOwnSlot(t *testing.T) {
	t.Cleanup(func() { setRunning("") })
	setRunning("slot-A")
	// A newer manual run overwrote the indicator; an older run finishing must
	// not clear the newer slot (which would show the page idle mid-run).
	clearRunning("slot-B")
	if got := getRunning(); got != "slot-A" {
		t.Fatalf("clearRunning(other) must not clear a newer slot; got %q, want slot-A", got)
	}
	clearRunning("slot-A")
	if got := getRunning(); got != "" {
		t.Fatalf("clearRunning(own) must clear; got %q, want empty", got)
	}
}

func TestConfigureNoOpAfterShutdown(t *testing.T) {
	cfgMu.Lock()
	configuredOnce = false
	activeCfg = defaultConfig()
	cfgMu.Unlock()
	configureMu.Lock()
	shuttingDown = false
	configureMu.Unlock()
	t.Cleanup(stopLoop)
	t.Cleanup(func() {
		configureMu.Lock()
		shuttingDown = false
		configureMu.Unlock()
		cfgMu.Lock()
		configuredOnce = false
		activeCfg = defaultConfig()
		cfgMu.Unlock()
	})

	// Simulate host teardown, then a configure() arriving afterward. It must be
	// a no-op: no loop (re)start, no active-config mutation. The host should not
	// reconfigure-after-shutdown, but we do not rely on host ordering.
	cliproxyPluginShutdown()
	dir := t.TempDir()
	raw := mustMarshal(t, lifecycleRequest{ConfigYAML: []byte("enabled: true\nstate_dir: \"" + dir + "\"\n")})
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	cfgMu.RLock()
	once := configuredOnce
	cfgMu.RUnlock()
	if once {
		t.Fatal("configure after shutdown must be a no-op (configuredOnce should stay false)")
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
