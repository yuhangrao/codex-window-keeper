package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const (
	abiVersion    uint32 = 1
	schemaVersion uint32 = 1

	methodPluginRegister     = "plugin.register"
	methodPluginReconfigure  = "plugin.reconfigure"
	methodSchedulerPick      = "scheduler.pick"
	methodManagementRegister = "management.register"
	methodManagementHandle   = "management.handle"
	methodHostAuthList       = "host.auth.list"
	methodHostModelExecute   = "host.model.execute"
	methodHostLog            = "host.log"

	pluginID      = "codex-window-keeper"
	pluginVersion = "0.3.0"

	defaultTargetHeader = "X-Codex-Window-Keeper-Target-Auth"
	defaultMarkerHeader = "X-Codex-Window-Keeper"
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type pluginConfig struct {
	Enabled                 bool
	Timezone                string
	Times                   []clockTime
	Model                   string
	Prompt                  string
	ReasoningEffort         string
	EntryProtocol           string
	ExitProtocol            string
	AuthDir                 string
	StateDir                string
	RunTimeout              time.Duration
	BetweenAuthDelay        time.Duration
	RetryDelay              time.Duration
	TargetHeader            string
	MarkerHeader            string
	StartupRun              bool
	DryRun                  bool
	IncludeUnavailableAuths bool
}

type clockTime struct {
	Hour   int
	Minute int
	Raw    string
}

type registration struct {
	SchemaVersion uint32       `json:"schema_version"`
	Metadata      metadata     `json:"metadata"`
	Capabilities  capabilities `json:"capabilities"`
}

type metadata struct {
	Name             string
	Version          string
	Author           string
	GitHubRepository string
	Logo             string
	ConfigFields     []configField
}

type configField struct {
	Name        string
	Type        string
	EnumValues  []string
	Description string
}

type capabilities struct {
	Scheduler     bool `json:"scheduler"`
	ManagementAPI bool `json:"management_api"`
}

type schedulerPickRequest struct {
	Provider   string
	Providers  []string
	Model      string
	Stream     bool
	Options    schedulerOptions
	Candidates []schedulerCandidate
}

type schedulerOptions struct {
	Headers  map[string][]string
	Metadata map[string]any
}

type schedulerCandidate struct {
	ID       string
	Provider string
	Priority int
	Status   string
}

type schedulerPickResponse struct {
	AuthID  string
	Handled bool
}

type authListResponse struct {
	Files []authEntry `json:"files"`
}

type authEntry struct {
	ID          string `json:"id"`
	AuthIndex   string `json:"auth_index"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Provider    string `json:"provider"`
	Label       string `json:"label"`
	Status      string `json:"status"`
	Disabled    bool   `json:"disabled"`
	Unavailable bool   `json:"unavailable"`
	RuntimeOnly bool   `json:"runtime_only"`
	Source      string `json:"source"`
	Path        string `json:"path"`
	Email       string `json:"email"`
	Note        string `json:"note"`
}

type hostModelExecutionRequest struct {
	EntryProtocol  string              `json:"entry_protocol"`
	ExitProtocol   string              `json:"exit_protocol"`
	Model          string              `json:"model"`
	Stream         bool                `json:"stream"`
	Body           []byte              `json:"body"`
	Headers        map[string][]string `json:"headers"`
	Query          map[string][]string `json:"query"`
	Alt            string              `json:"alt"`
	HostCallbackID string              `json:"host_callback_id,omitempty"`
}

type hostModelExecutionResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"body"`
}

type responsesRequest struct {
	Model     string               `json:"model"`
	Input     []responsesInputItem `json:"input"`
	Reasoning map[string]any       `json:"reasoning,omitempty"`
	Store     bool                 `json:"store"`
}

// responsesInputItem is one entry in the Responses API `input` array. The codex
// exit protocol requires `input` to be a list of structured items; a bare
// string is forwarded unchanged and rejected upstream with
// {"detail":"Input must be a list"}.
type responsesInputItem struct {
	Type    string                 `json:"type"`
	Role    string                 `json:"role"`
	Content []responsesContentPart `json:"content"`
}

type responsesContentPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type hostLogRequest struct {
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

type managementRegistration struct {
	Resources []resourceRoute `json:"resources,omitempty"`
}

type resourceRoute struct {
	Path        string
	Menu        string
	Description string
}

type managementRequest struct {
	Method string
	Path   string
	Query  map[string][]string
	Body   []byte
}

type managementResponse struct {
	StatusCode int                 `json:"StatusCode"`
	Headers    map[string][]string `json:"Headers"`
	Body       []byte              `json:"Body"`
}

type stateFile struct {
	Attempts map[string]attemptRecord `json:"attempts"`
}

type attemptRecord struct {
	Slot          string `json:"slot"`
	AuthID        string `json:"auth_id"`
	AuthName      string `json:"auth_name,omitempty"`
	StartedAt     string `json:"started_at"`
	TargetAt      string `json:"target_at,omitempty"`
	LastAttemptAt string `json:"last_attempt_at,omitempty"`
	SentAt        string `json:"sent_at,omitempty"`
	Status        string `json:"status"`
	AttemptCount  int    `json:"attempt_count,omitempty"`
	Error         string `json:"error,omitempty"`
}

type runSummary struct {
	Slot      string          `json:"slot"`
	StartedAt string          `json:"started_at"`
	DryRun    bool            `json:"dry_run"`
	Results   []attemptRecord `json:"results"`
}

var (
	cfgMu      sync.RWMutex
	activeCfg  = defaultConfig()
	loopCancel context.CancelFunc

	runMu       sync.Mutex
	stateMu     sync.Mutex
	statePath   string
	keeperState = stateFile{Attempts: map[string]attemptRecord{}}

	lastSummaryMu sync.Mutex
	lastSummary   runSummary

	runningMu   sync.Mutex
	runningSlot string // non-empty while a runSlot is active; drives the status-page live refresh
)

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(abiVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, err := handleMethod(C.GoString(method), requestBytes)
	if err != nil {
		writeResponse(response, errorEnvelope("plugin_error", err.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	stopLoop()
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case methodPluginRegister, methodPluginReconfigure:
		if err := configure(request); err != nil {
			return nil, err
		}
		return okEnvelope(pluginRegistration())
	case methodSchedulerPick:
		return pickAuth(request)
	case methodManagementRegister:
		return okEnvelope(managementRegistration{Resources: []resourceRoute{{
			Path:        "/status",
			Menu:        "Codex Window Keeper",
			Description: "Shows Codex keepalive schedule and last run status.",
		}}})
	case methodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	cfg := defaultConfig()
	var req lifecycleRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("decode lifecycle request: %w", err)
		}
	}
	if len(req.ConfigYAML) > 0 {
		if err := applyConfigYAML(&cfg, req.ConfigYAML); err != nil {
			return err
		}
	}
	cfg.normalize()

	stopLoop()
	if err := loadState(cfg.StateDir); err != nil {
		hostLog("warn", "codex-window-keeper state load failed", map[string]any{"error": err.Error()})
	}
	cfgMu.Lock()
	activeCfg = cfg
	cfgMu.Unlock()
	if cfg.Enabled {
		startLoop(cfg)
	}
	hostLog("info", "codex-window-keeper configured", map[string]any{
		"timezone": cfg.Timezone,
		"times":    clockTimesToStrings(cfg.Times),
		"model":    cfg.Model,
		"dry_run":  cfg.DryRun,
	})
	return nil
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: schemaVersion,
		Metadata: metadata{
			Name:             pluginID,
			Version:          pluginVersion,
			Author:           "local",
			GitHubRepository: "https://github.com/router-for-me/CLIProxyAPI",
			Logo:             "",
			ConfigFields: []configField{
				{Name: "timezone", Type: "string", Description: "IANA timezone used for daily schedule, e.g. Asia/Shanghai."},
				{Name: "times", Type: "array", Description: "Daily HH:MM keepalive times."},
				{Name: "model", Type: "string", Description: "Model used for keepalive requests."},
				{Name: "reasoning_effort", Type: "enum", EnumValues: []string{"minimal", "low", "medium", "high"}, Description: "Responses API reasoning effort."},
				{Name: "prompt", Type: "string", Description: "Prompt sent to each Codex auth."},
				{Name: "auth_dir", Type: "string", Description: "Fallback local auth directory used when the host auth-list callback is unavailable."},
				{Name: "retry_delay_seconds", Type: "number", Description: "Delay before retrying auths that have not succeeded in the current slot."},
				{Name: "dry_run", Type: "boolean", Description: "When true, record attempts without sending model requests."},
			},
		},
		Capabilities: capabilities{
			Scheduler:     true,
			ManagementAPI: true,
		},
	}
}

func defaultConfig() pluginConfig {
	return pluginConfig{
		Enabled:          true,
		Timezone:         "Asia/Shanghai",
		Times:            mustParseClockTimes([]string{"07:00", "12:00", "17:00", "22:00"}),
		Model:            "gpt-5.4",
		Prompt:           "hi",
		ReasoningEffort:  "low",
		EntryProtocol:    "responses",
		ExitProtocol:     "codex",
		AuthDir:          "/root/.cli-proxy-api",
		StateDir:         "/CLIProxyAPI/codex-window-keeper-state",
		RunTimeout:       10 * time.Minute,
		BetweenAuthDelay: 2 * time.Second,
		RetryDelay:       15 * time.Second,
		TargetHeader:     defaultTargetHeader,
		MarkerHeader:     defaultMarkerHeader,
		StartupRun:       false,
		DryRun:           false,
	}
}

func (cfg *pluginConfig) normalize() {
	cfg.Timezone = strings.TrimSpace(cfg.Timezone)
	if cfg.Timezone == "" {
		cfg.Timezone = "Asia/Shanghai"
	}
	if len(cfg.Times) == 0 {
		cfg.Times = mustParseClockTimes([]string{"07:00", "12:00", "17:00", "22:00"})
	}
	sort.Slice(cfg.Times, func(i, j int) bool {
		if cfg.Times[i].Hour == cfg.Times[j].Hour {
			return cfg.Times[i].Minute < cfg.Times[j].Minute
		}
		return cfg.Times[i].Hour < cfg.Times[j].Hour
	})
	cfg.Model = strings.TrimSpace(cfg.Model)
	if cfg.Model == "" {
		cfg.Model = "gpt-5.4"
	}
	cfg.Prompt = strings.TrimSpace(cfg.Prompt)
	if cfg.Prompt == "" {
		cfg.Prompt = "hi"
	}
	cfg.ReasoningEffort = strings.ToLower(strings.TrimSpace(cfg.ReasoningEffort))
	if cfg.ReasoningEffort == "" {
		cfg.ReasoningEffort = "low"
	}
	cfg.EntryProtocol = strings.TrimSpace(cfg.EntryProtocol)
	if cfg.EntryProtocol == "" {
		cfg.EntryProtocol = "responses"
	}
	cfg.ExitProtocol = strings.TrimSpace(cfg.ExitProtocol)
	if cfg.ExitProtocol == "" {
		cfg.ExitProtocol = "codex"
	}
	cfg.AuthDir = strings.TrimSpace(cfg.AuthDir)
	if cfg.AuthDir == "" {
		cfg.AuthDir = "/root/.cli-proxy-api"
	}
	cfg.StateDir = strings.TrimSpace(cfg.StateDir)
	if cfg.StateDir == "" {
		cfg.StateDir = "/CLIProxyAPI/codex-window-keeper-state"
	}
	if cfg.RunTimeout <= 0 {
		cfg.RunTimeout = 10 * time.Minute
	}
	if cfg.BetweenAuthDelay < 0 {
		cfg.BetweenAuthDelay = 0
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = 15 * time.Second
	}
	cfg.TargetHeader = strings.TrimSpace(cfg.TargetHeader)
	if cfg.TargetHeader == "" {
		cfg.TargetHeader = defaultTargetHeader
	}
	cfg.MarkerHeader = strings.TrimSpace(cfg.MarkerHeader)
	if cfg.MarkerHeader == "" {
		cfg.MarkerHeader = defaultMarkerHeader
	}
}

func applyConfigYAML(cfg *pluginConfig, raw []byte) error {
	lines := strings.Split(string(raw), "\n")
	for i := 0; i < len(lines); i++ {
		line := stripYAMLComment(lines[i])
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := countLeadingSpaces(line)
		if indent != 0 {
			continue
		}
		key, value, ok := splitYAMLKeyValue(line)
		if !ok {
			continue
		}
		key = normalizeKey(key)
		switch key {
		case "enabled":
			if v, ok := parseBool(value); ok {
				cfg.Enabled = v
			}
		case "timezone":
			cfg.Timezone = unquote(value)
		case "times":
			values := parseInlineList(value)
			if len(values) == 0 {
				for j := i + 1; j < len(lines); j++ {
					child := stripYAMLComment(lines[j])
					if strings.TrimSpace(child) == "" {
						continue
					}
					if countLeadingSpaces(child) <= indent {
						break
					}
					trimmed := strings.TrimSpace(child)
					if strings.HasPrefix(trimmed, "- ") {
						values = append(values, unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))))
						i = j
					}
				}
			}
			if parsed, err := parseClockTimes(values); err != nil {
				return err
			} else if len(parsed) > 0 {
				cfg.Times = parsed
			}
		case "model":
			cfg.Model = unquote(value)
		case "prompt":
			cfg.Prompt = unquote(value)
		case "reasoning_effort":
			cfg.ReasoningEffort = unquote(value)
		case "entry_protocol":
			cfg.EntryProtocol = unquote(value)
		case "exit_protocol":
			cfg.ExitProtocol = unquote(value)
		case "auth_dir", "auth-dir":
			cfg.AuthDir = unquote(value)
		case "state_dir":
			cfg.StateDir = unquote(value)
		case "run_timeout_seconds":
			if seconds, ok := parseInt(value); ok {
				cfg.RunTimeout = time.Duration(seconds) * time.Second
			}
		case "between_auth_delay_seconds":
			if seconds, ok := parseInt(value); ok {
				cfg.BetweenAuthDelay = time.Duration(seconds) * time.Second
			}
		case "retry_delay_seconds":
			if seconds, ok := parseInt(value); ok {
				cfg.RetryDelay = time.Duration(seconds) * time.Second
			}
		case "target_header":
			cfg.TargetHeader = unquote(value)
		case "marker_header":
			cfg.MarkerHeader = unquote(value)
		case "startup_run":
			if v, ok := parseBool(value); ok {
				cfg.StartupRun = v
			}
		case "dry_run":
			if v, ok := parseBool(value); ok {
				cfg.DryRun = v
			}
		case "include_unavailable_auths":
			if v, ok := parseBool(value); ok {
				cfg.IncludeUnavailableAuths = v
			}
		}
	}
	return nil
}

func startLoop(cfg pluginConfig) {
	ctx, cancel := context.WithCancel(context.Background())
	cfgMu.Lock()
	loopCancel = cancel
	cfgMu.Unlock()
	go scheduleLoop(ctx, cfg)
	if cfg.StartupRun {
		go runSlot(context.Background(), cfg, "startup", true)
	}
}

func stopLoop() {
	cfgMu.Lock()
	cancel := loopCancel
	loopCancel = nil
	cfgMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func scheduleLoop(ctx context.Context, cfg pluginConfig) {
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		hostLog("warn", "codex-window-keeper timezone load failed, using local time", map[string]any{"timezone": cfg.Timezone, "error": err.Error()})
		loc = time.Local
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	lastFiredSlot := ""
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			localNow := now.In(loc)
			for _, scheduled := range cfg.Times {
				if localNow.Hour() == scheduled.Hour && localNow.Minute() == scheduled.Minute {
					slot := localNow.Format("2006-01-02") + " " + scheduled.Raw
					if slot == lastFiredSlot {
						continue
					}
					lastFiredSlot = slot
					go runSlot(ctx, cfg, slot, false)
				}
			}
		}
	}
}

func runSlot(parent context.Context, cfg pluginConfig, slot string, manual bool) {
	runMu.Lock()
	defer runMu.Unlock()
	setRunning(slot)
	defer setRunning("")

	startedAt := time.Now().UTC().Format(time.RFC3339)
	summary := runSummary{Slot: slot, StartedAt: startedAt, DryRun: cfg.DryRun}
	listCtx, listCancel := context.WithTimeout(parent, 30*time.Second)
	auths, err := listCodexAuths(listCtx, cfg)
	listCancel()
	if err != nil {
		record := attemptRecord{Slot: slot, StartedAt: startedAt, Status: "list_failed", Error: err.Error()}
		summary.Results = append(summary.Results, record)
		setLastSummary(summary)
		hostLog("error", "codex-window-keeper failed to list auths", map[string]any{"slot": slot, "error": err.Error()})
		return
	}

	loc := mustLocation(cfg.Timezone)
	nominalAt, hasNominalAt := parseNominalSlot(slot, loc)
	targetTimes := map[string]time.Time{}
	latestTarget := time.Now()
	for _, auth := range auths {
		targetAt := time.Now()
		if hasNominalAt {
			targetAt = nominalAt.Add(dailyOffsetBeforeSlot(auth.ID, nominalAt, cfg, loc))
		}
		targetAt = targetAt.Truncate(time.Second)
		targetTimes[auth.ID] = targetAt
		if targetAt.After(latestTarget) {
			latestTarget = targetAt
		}
	}
	deadline := latestTarget.Add(cfg.RunTimeout)
	if deadline.Before(time.Now().Add(cfg.RunTimeout)) {
		deadline = time.Now().Add(cfg.RunTimeout)
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()

	pending := make(map[string]authEntry, len(auths))
	latest := make(map[string]attemptRecord, len(auths))
	for _, auth := range auths {
		key := attemptKey(slot, auth.ID)
		if record, ok := getAttempt(key); ok && isTerminalSuccess(record) {
			record.Status = "skipped_sent"
			latest[auth.ID] = record
			continue
		}
		pending[auth.ID] = auth
	}

	for len(pending) > 0 {
		nextWake := time.Time{}
		for index, auth := range auths {
			if _, ok := pending[auth.ID]; !ok {
				continue
			}
			select {
			case <-ctx.Done():
				summary.Results = recordsFromMap(latest)
				setLastSummary(summary)
				return
			default:
			}
			targetAt := targetTimes[auth.ID]
			if now := time.Now(); now.Before(targetAt) {
				if nextWake.IsZero() || targetAt.Before(nextWake) {
					nextWake = targetAt
				}
				continue
			}

			key := attemptKey(slot, auth.ID)
			record, ok := getAttempt(key)
			if !ok {
				record = attemptRecord{
					Slot:      slot,
					AuthID:    auth.ID,
					AuthName:  auth.Name,
					StartedAt: startedAt,
				}
			}
			if isTerminalSuccess(record) {
				record.Status = "skipped_sent"
				latest[auth.ID] = record
				delete(pending, auth.ID)
				continue
			}

			record.AuthName = auth.Name
			record.TargetAt = targetAt.Format(time.RFC3339)
			record.LastAttemptAt = time.Now().UTC().Format(time.RFC3339)
			record.AttemptCount++
			record.Status = "attempting"
			record.Error = ""
			if errState := updateAttempt(key, record); errState != nil {
				record.Status = "state_failed"
				record.Error = errState.Error()
				latest[auth.ID] = record
				hostLog("warn", "codex-window-keeper failed to persist attempt", map[string]any{"slot": slot, "auth_id": auth.ID, "error": errState.Error()})
				continue
			}

			if cfg.DryRun {
				record.Status = "dry_run"
				_ = updateAttempt(key, record)
				latest[auth.ID] = record
				delete(pending, auth.ID)
				continue
			}

			errSend := sendHi(ctx, cfg, slot, auth)
			if errSend != nil {
				record.Status = "failed"
				record.Error = errSend.Error()
				_ = updateAttempt(key, record)
				latest[auth.ID] = record
				hostLog("warn", "codex-window-keeper keepalive failed; will retry while slot is active", map[string]any{"slot": slot, "auth_id": auth.ID, "name": auth.Name, "attempt": record.AttemptCount, "error": errSend.Error()})
			} else {
				record.Status = "sent"
				record.SentAt = time.Now().UTC().Format(time.RFC3339)
				record.Error = ""
				if errState := updateAttempt(key, record); errState != nil {
					record.Status = "sent_state_failed"
					record.Error = errState.Error()
					latest[auth.ID] = record
					delete(pending, auth.ID)
					hostLog("error", "codex-window-keeper keepalive sent but failed to persist success", map[string]any{"slot": slot, "auth_id": auth.ID, "name": auth.Name, "attempt": record.AttemptCount, "error": errState.Error()})
				} else {
					latest[auth.ID] = record
					delete(pending, auth.ID)
					hostLog("info", "codex-window-keeper keepalive sent", map[string]any{"slot": slot, "auth_id": auth.ID, "name": auth.Name, "attempt": record.AttemptCount})
				}
			}

			if index < len(auths)-1 && cfg.BetweenAuthDelay > 0 {
				select {
				case <-ctx.Done():
					summary.Results = recordsFromMap(latest)
					setLastSummary(summary)
					return
				case <-time.After(cfg.BetweenAuthDelay):
				}
			}
		}

		if len(pending) > 0 {
			sleepUntil := time.Now().Add(cfg.RetryDelay)
			if !nextWake.IsZero() && nextWake.Before(sleepUntil) {
				sleepUntil = nextWake
			}
			sleepFor := time.Until(sleepUntil)
			if sleepFor < 0 {
				sleepFor = 0
			}
			select {
			case <-ctx.Done():
				summary.Results = recordsFromMap(latest)
				setLastSummary(summary)
				return
			case <-time.After(sleepFor):
			}
		}
	}
	summary.Results = recordsFromMap(latest)
	setLastSummary(summary)
	if manual {
		hostLog("info", "codex-window-keeper manual run completed", map[string]any{"slot": slot, "count": len(summary.Results)})
	}
}

func listCodexAuths(ctx context.Context, cfg pluginConfig) ([]authEntry, error) {
	result, err := callHost(ctx, methodHostAuthList, map[string]any{})
	if err != nil {
		auths, fallbackErr := listCodexAuthsFromDir(cfg)
		if fallbackErr != nil {
			return nil, fmt.Errorf("%w; fallback auth dir failed: %v", err, fallbackErr)
		}
		hostLog("warn", "codex-window-keeper host auth list unavailable; using auth dir fallback", map[string]any{"auth_dir": cfg.AuthDir, "count": len(auths), "error": err.Error()})
		return auths, nil
	}
	var resp authListResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("decode host auth list: %w", err)
	}
	return normalizeAuthEntries(resp.Files, cfg), nil
}

func normalizeAuthEntries(entries []authEntry, cfg pluginConfig) []authEntry {
	out := make([]authEntry, 0, len(entries))
	seen := map[string]struct{}{}
	for _, entry := range entries {
		if !isCodexFileAuth(entry) {
			continue
		}
		if entry.Disabled {
			continue
		}
		if entry.Unavailable && !cfg.IncludeUnavailableAuths {
			continue
		}
		if entry.ID == "" {
			entry.ID = entry.Name
		}
		if entry.ID == "" {
			continue
		}
		if _, ok := seen[entry.ID]; ok {
			continue
		}
		seen[entry.ID] = struct{}{}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func listCodexAuthsFromDir(cfg pluginConfig) ([]authEntry, error) {
	entries, err := os.ReadDir(cfg.AuthDir)
	if err != nil {
		return nil, err
	}
	auths := make([]authEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, "codex-") || !strings.HasSuffix(lower, ".json") {
			continue
		}
		auths = append(auths, authEntry{
			ID:       name,
			Name:     name,
			Type:     "codex",
			Provider: "codex",
			Source:   "file",
			Path:     filepath.Join(cfg.AuthDir, name),
		})
	}
	return normalizeAuthEntries(auths, cfg), nil
}

func isCodexFileAuth(entry authEntry) bool {
	provider := strings.ToLower(strings.TrimSpace(firstNonEmpty(entry.Provider, entry.Type)))
	if provider != "codex" {
		return false
	}
	if entry.RuntimeOnly {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(entry.Source), "memory") && strings.TrimSpace(entry.Path) == "" {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(entry.Name))
	return strings.HasPrefix(name, "codex-") && strings.HasSuffix(name, ".json")
}

func sendHi(ctx context.Context, cfg pluginConfig, slot string, auth authEntry) error {
	body, err := keepaliveBody(cfg)
	if err != nil {
		return err
	}
	sid := sessionID(slot, auth.ID)
	headers := map[string][]string{
		"Content-Type":        {"application/json"},
		cfg.MarkerHeader:      {"1"},
		cfg.TargetHeader:      {auth.ID},
		"X-Session-ID":        {sid},
		"Session-Id":          {sid},
		"X-Client-Request-Id": {sid},
		"Idempotency-Key":     {sid},
	}
	result, err := callHost(ctx, methodHostModelExecute, hostModelExecutionRequest{
		EntryProtocol: cfg.EntryProtocol,
		ExitProtocol:  cfg.ExitProtocol,
		Model:         cfg.Model,
		Stream:        false,
		Body:          body,
		Headers:       headers,
		Query:         map[string][]string{},
	})
	if err != nil {
		return err
	}
	var resp hostModelExecutionResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		return fmt.Errorf("decode host.model.execute: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("host.model.execute status %d: %s", resp.StatusCode, truncateForLog(string(resp.Body), 500))
	}
	return nil
}

func keepaliveBody(cfg pluginConfig) ([]byte, error) {
	// The codex backend rejects a `metadata` field ("Unsupported parameter:
	// metadata"), so keepalive traceability lives in the request headers
	// (marker, target auth, session/idempotency keys) and the state file, not
	// in the body.
	req := responsesRequest{
		Model: cfg.Model,
		Input: []responsesInputItem{{
			Type:    "message",
			Role:    "user",
			Content: []responsesContentPart{{Type: "input_text", Text: cfg.Prompt}},
		}},
		Store: false,
	}
	if cfg.ReasoningEffort != "" {
		req.Reasoning = map[string]any{"effort": cfg.ReasoningEffort}
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal keepalive request: %w", err)
	}
	return raw, nil
}

func pickAuth(raw []byte) ([]byte, error) {
	var req schedulerPickRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	cfg := currentConfig()
	marker := headerGet(req.Options.Headers, cfg.MarkerHeader)
	target := strings.TrimSpace(headerGet(req.Options.Headers, cfg.TargetHeader))
	if marker != "1" && !strings.EqualFold(marker, "true") {
		return okEnvelope(schedulerPickResponse{Handled: false})
	}
	if target == "" {
		return errorEnvelope("keeper_target_missing", "codex-window-keeper target auth header is missing"), nil
	}
	for _, candidate := range req.Candidates {
		if candidate.ID == target {
			return okEnvelope(schedulerPickResponse{AuthID: target, Handled: true})
		}
	}
	return errorEnvelope("keeper_target_unavailable", "target auth is not available for this request: "+target), nil
}

func handleManagement(raw []byte) ([]byte, error) {
	var req managementRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, fmt.Errorf("decode management request: %w", err)
		}
	}
	queryRun := queryGet(req.Query, "run")
	if queryRun == "1" || strings.EqualFold(queryRun, "true") {
		cfg := currentConfig()
		slot := "manual-" + time.Now().In(mustLocation(cfg.Timezone)).Format("2006-01-02 15:04:05")
		setRunning(slot)
		go runSlot(context.Background(), cfg, slot, true)
		// Redirect to the query-less page so the browser (and its auto-refresh)
		// shows live progress without re-triggering the run on every reload.
		return okEnvelope(managementResponse{
			StatusCode: http.StatusSeeOther,
			Headers:    map[string][]string{"Location": {"status"}},
		})
	}
	page := renderStatusPage()
	return okEnvelope(managementResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string][]string{"content-type": {"text/html; charset=utf-8"}},
		Body:       page,
	})
}

func renderStatusPage() []byte {
	cfg := currentConfig()
	summary := getLastSummary()
	running := getRunning()
	loc := mustLocation(cfg.Timezone)
	stateMu.Lock()
	attemptCount := len(keeperState.Attempts)
	stateMu.Unlock()

	authCount := ""
	authErr := ""
	authCheckCtx, authCheckCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if auths, err := listCodexAuths(authCheckCtx, cfg); err == nil {
		authCount = strconv.Itoa(len(auths))
	} else {
		authErr = err.Error()
	}
	authCheckCancel()

	enabledBadge := `<span class="badge bad">disabled</span>`
	if cfg.Enabled {
		enabledBadge = `<span class="badge ok">enabled</span>`
	}

	var out bytes.Buffer
	out.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">`)
	if running != "" {
		// Auto-refresh to the query-less path while a run is active so progress
		// streams in; stops once the run finishes and the flag clears.
		out.WriteString(`<meta http-equiv="refresh" content="3;url=status">`)
	}
	out.WriteString(`<title>Codex Window Keeper</title><style>`)
	out.WriteString(statusPageCSS)
	out.WriteString(`</style></head><body><main class="wrap"><header class="hd"><div><h1>Codex Window Keeper</h1><p class="sub">Pins each file-based Codex credential&#39;s 5h limit window to fixed daily slots.</p></div><span class="ver">v`)
	out.WriteString(html.EscapeString(pluginVersion))
	out.WriteString(`</span></header><section class="cards">`)
	writeCard(&out, "Status", enabledBadge)
	if authErr == "" {
		writeCard(&out, "Codex credentials", html.EscapeString(authCount))
	} else {
		writeCard(&out, "Codex credentials", `<span class="badge bad">error</span>`)
	}
	writeCard(&out, "Timezone", html.EscapeString(cfg.Timezone))
	writeCard(&out, "Model", html.EscapeString(cfg.Model))
	writeCard(&out, "Reasoning effort", html.EscapeString(cfg.ReasoningEffort))
	writeCard(&out, "Attempts recorded", strconv.Itoa(attemptCount))
	out.WriteString(`</section>`)

	if authErr != "" {
		out.WriteString(`<p class="muted mono">auth list error: `)
		out.WriteString(html.EscapeString(authErr))
		out.WriteString(`</p>`)
	}

	out.WriteString(`<h2>Daily schedule</h2><div class="slots">`)
	for _, t := range clockTimesToStrings(cfg.Times) {
		out.WriteString(`<span class="slot">`)
		out.WriteString(html.EscapeString(t))
		out.WriteString(`</span>`)
	}
	out.WriteString(`</div><p class="muted mono">state_dir: `)
	out.WriteString(html.EscapeString(cfg.StateDir))
	out.WriteString(`</p><p class="action"><a class="btn" href="?run=1">Run once now</a><span class="hint">sends a real &quot;`)
	out.WriteString(html.EscapeString(cfg.Prompt))
	out.WriteString(`&quot; to each available credential</span></p>`)

	// Run section: live view (from persisted attempts) while a run is active,
	// otherwise the last completed run summary.
	var runSlotName, runStarted string
	var results []attemptRecord
	dryRun := false
	if running != "" {
		out.WriteString(`<h2>Current run <span class="badge warn">running…</span></h2>`)
		runSlotName = running
		results = attemptsForSlot(running)
		if len(results) > 0 {
			runStarted = results[0].StartedAt
		}
		dryRun = cfg.DryRun
	} else {
		out.WriteString(`<h2>Last run</h2>`)
		runSlotName = summary.Slot
		runStarted = summary.StartedAt
		results = summary.Results
		dryRun = summary.DryRun
	}

	if runSlotName == "" {
		out.WriteString(`<p class="muted">No run recorded yet.</p>`)
	} else {
		out.WriteString(`<p class="muted">slot <span class="mono">`)
		out.WriteString(html.EscapeString(runSlotName))
		out.WriteString(`</span>`)
		if runStarted != "" {
			out.WriteString(` &middot; started <span class="mono">`)
			out.WriteString(html.EscapeString(fmtClockOrRaw(runStarted, loc)))
			out.WriteString(`</span>`)
		}
		if dryRun {
			out.WriteString(` &middot; <span class="badge muted">dry run</span>`)
		}
		out.WriteString(`</p>`)
		if len(results) == 0 {
			out.WriteString(`<p class="muted">Starting&hellip;</p>`)
		} else {
			out.WriteString(`<table><thead><tr><th>Credential</th><th>Status</th><th>Target</th><th>Sent / last try</th><th>Tries</th><th>Detail</th></tr></thead><tbody>`)
			for _, r := range results {
				sentOrLast := r.SentAt
				if sentOrLast == "" {
					sentOrLast = r.LastAttemptAt
				}
				out.WriteString(`<tr><td>`)
				out.WriteString(html.EscapeString(displayAuthName(r)))
				out.WriteString(`</td><td><span class="badge `)
				out.WriteString(badgeClass(r.Status))
				out.WriteString(`">`)
				out.WriteString(html.EscapeString(r.Status))
				out.WriteString(`</span></td><td class="mono">`)
				out.WriteString(html.EscapeString(fmtClockOrRaw(r.TargetAt, loc)))
				out.WriteString(`</td><td class="mono">`)
				out.WriteString(html.EscapeString(fmtClockOrRaw(sentOrLast, loc)))
				out.WriteString(`</td><td>`)
				out.WriteString(strconv.Itoa(r.AttemptCount))
				out.WriteString(`</td><td class="err">`)
				out.WriteString(html.EscapeString(r.Error))
				out.WriteString(`</td></tr>`)
			}
			out.WriteString(`</tbody></table>`)
		}
	}

	out.WriteString(`</main></body></html>`)
	return out.Bytes()
}

const statusPageCSS = `:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1f2933;background:#f7f8fa}
.wrap{max-width:920px;margin:0 auto;padding:2rem 1.25rem 3rem}
.hd{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1.5rem}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.05rem;margin:2rem 0 .75rem;font-weight:600}
.sub{margin:0;color:#6b7280}
.ver{font:600 .75rem/1 ui-monospace,SFMono-Regular,Menlo,monospace;color:#6b7280;border:1px solid #d1d5db;border-radius:999px;padding:.35rem .6rem;white-space:nowrap}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:.75rem}
.card{border:1px solid #e5e7eb;border-radius:12px;padding:.8rem .9rem;background:#fff}
.card .k{display:block;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;margin-bottom:.4rem}
.card .v{font-size:1.05rem;font-weight:600;word-break:break-word}
.badge{display:inline-block;font:600 .78rem/1.4 inherit;padding:.15rem .55rem;border-radius:999px}
.badge.ok{background:#dcfce7;color:#067647}
.badge.bad{background:#fee2e2;color:#b42318}
.badge.warn{background:#fef3c7;color:#92400e}
.badge.muted{background:#e5e7eb;color:#374151}
.slots{display:flex;flex-wrap:wrap;gap:.5rem}
.slot{font:600 .85rem/1 ui-monospace,SFMono-Regular,Menlo,monospace;border:1px solid #d1d5db;border-radius:8px;padding:.45rem .7rem;background:#fff}
.action{margin-top:1.5rem;display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.btn{display:inline-block;text-decoration:none;font-weight:600;background:#4f46e5;color:#fff;padding:.55rem 1rem;border-radius:10px}
.btn:hover{background:#4338ca}
.hint{color:#6b7280;font-size:.85rem}
.muted{color:#6b7280}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem}
table{width:100%;border-collapse:collapse;font-size:.9rem;margin-top:.25rem}
th,td{text-align:left;padding:.55rem .6rem;border-bottom:1px solid #e5e7eb;vertical-align:top}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;font-weight:600}
td.err{color:#b42318;max-width:340px;word-break:break-word;font-size:.82rem}
@media (prefers-color-scheme:dark){
body{color:#e5e7eb;background:#0f1216}
.sub,.ver,.hint,.muted,.card .k,th{color:#9ca3af}
.card,.slot{background:#161a20;border-color:#2a2f37}
.ver,.slot{border-color:#2a2f37}
th,td{border-color:#2a2f37}
.badge.ok{background:#06351f;color:#4ade80}
.badge.bad{background:#3f1417;color:#fca5a5}
.badge.warn{background:#3a2c08;color:#fcd34d}
.badge.muted{background:#23272e;color:#cbd5e1}
td.err{color:#fca5a5}
}`

func writeCard(out *bytes.Buffer, key, valueHTML string) {
	// valueHTML is trusted markup (a badge) or already HTML-escaped by the caller.
	out.WriteString(`<div class="card"><span class="k">`)
	out.WriteString(html.EscapeString(key))
	out.WriteString(`</span><span class="v">`)
	out.WriteString(valueHTML)
	out.WriteString(`</span></div>`)
}

func badgeClass(status string) string {
	switch status {
	case "sent", "skipped_sent":
		return "ok"
	case "attempting":
		return "warn"
	case "dry_run", "":
		return "muted"
	default:
		return "bad"
	}
}

func displayAuthName(r attemptRecord) string {
	if strings.TrimSpace(r.AuthName) != "" {
		return r.AuthName
	}
	if strings.TrimSpace(r.AuthID) != "" {
		return r.AuthID
	}
	return "(unknown)"
}

func fmtClockOrRaw(rfc3339 string, loc *time.Location) string {
	if strings.TrimSpace(rfc3339) == "" {
		return "—"
	}
	if t, err := time.Parse(time.RFC3339, rfc3339); err == nil {
		return t.In(loc).Format("01-02 15:04:05")
	}
	return rfc3339
}

func currentConfig() pluginConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return activeCfg
}

func loadState(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "state.json")
	next := stateFile{Attempts: map[string]attemptRecord{}}
	if raw, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &next); err != nil {
			return err
		}
		if next.Attempts == nil {
			next.Attempts = map[string]attemptRecord{}
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	stateMu.Lock()
	statePath = path
	keeperState = next
	stateMu.Unlock()
	return nil
}

func getAttempt(key string) (attemptRecord, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	if keeperState.Attempts == nil {
		return attemptRecord{}, false
	}
	record, ok := keeperState.Attempts[key]
	return record, ok
}

func updateAttempt(key string, record attemptRecord) error {
	stateMu.Lock()
	defer stateMu.Unlock()
	if keeperState.Attempts == nil {
		keeperState.Attempts = map[string]attemptRecord{}
	}
	keeperState.Attempts[key] = record
	return saveStateLocked()
}

func saveStateLocked() error {
	if statePath == "" {
		return fmt.Errorf("state path is empty")
	}
	raw, err := json.MarshalIndent(keeperState, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath)
}

func dailyOffsetBeforeSlot(authID string, nominalAt time.Time, cfg pluginConfig, loc *time.Location) time.Duration {
	if isFirstDailySlot(nominalAt, cfg) {
		return 0
	}
	stateMu.Lock()
	defer stateMu.Unlock()
	var bestNominal time.Time
	var bestSent time.Time
	for _, record := range keeperState.Attempts {
		if record.AuthID != authID || record.Status != "sent" || record.SentAt == "" {
			continue
		}
		recordNominal, ok := parseNominalSlot(record.Slot, loc)
		if !ok || !sameLocalDate(recordNominal, nominalAt) || !recordNominal.Before(nominalAt) {
			continue
		}
		sentAt, err := time.Parse(time.RFC3339, record.SentAt)
		if err != nil {
			continue
		}
		if bestNominal.IsZero() || recordNominal.After(bestNominal) {
			bestNominal = recordNominal
			bestSent = sentAt
		}
	}
	if bestNominal.IsZero() {
		return 0
	}
	offset := bestSent.In(loc).Sub(bestNominal)
	if offset < 0 {
		return 0
	}
	return offset.Truncate(time.Second)
}

func parseNominalSlot(slot string, loc *time.Location) (time.Time, bool) {
	nominalAt, err := time.ParseInLocation("2006-01-02 15:04", slot, loc)
	if err != nil {
		return time.Time{}, false
	}
	return nominalAt, true
}

func sameLocalDate(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

func isFirstDailySlot(nominalAt time.Time, cfg pluginConfig) bool {
	if len(cfg.Times) == 0 {
		return false
	}
	first := cfg.Times[0]
	for _, item := range cfg.Times[1:] {
		if item.Hour < first.Hour || (item.Hour == first.Hour && item.Minute < first.Minute) {
			first = item
		}
	}
	return nominalAt.Hour() == first.Hour && nominalAt.Minute() == first.Minute
}

func attemptKey(slot, authID string) string {
	return slot + "|" + authID
}

func isTerminalSuccess(record attemptRecord) bool {
	return record.Status == "sent"
}

func recordsFromMap(records map[string]attemptRecord) []attemptRecord {
	out := make([]attemptRecord, 0, len(records))
	for _, record := range records {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].AuthName) < strings.ToLower(out[j].AuthName)
	})
	return out
}

func setLastSummary(summary runSummary) {
	lastSummaryMu.Lock()
	lastSummary = summary
	lastSummaryMu.Unlock()
}

func setRunning(slot string) {
	runningMu.Lock()
	runningSlot = slot
	runningMu.Unlock()
}

func getRunning() string {
	runningMu.Lock()
	defer runningMu.Unlock()
	return runningSlot
}

// attemptsForSlot returns the persisted attempt records for one slot, sorted by
// credential name. It backs the live run view, which reads current state on
// every page refresh instead of waiting for the run to finish.
func attemptsForSlot(slot string) []attemptRecord {
	stateMu.Lock()
	defer stateMu.Unlock()
	out := make([]attemptRecord, 0, len(keeperState.Attempts))
	for _, record := range keeperState.Attempts {
		if record.Slot == slot {
			out = append(out, record)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].AuthName) < strings.ToLower(out[j].AuthName)
	})
	return out
}

func getLastSummary() runSummary {
	lastSummaryMu.Lock()
	defer lastSummaryMu.Unlock()
	return lastSummary
}

func callHost(ctx context.Context, method string, payload any) (json.RawMessage, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal host callback %s: %w", method, err)
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))

	var response C.cliproxy_buffer
	var requestPtr *C.uint8_t
	if len(rawPayload) > 0 {
		cPayload := C.CBytes(rawPayload)
		if cPayload == nil {
			return nil, fmt.Errorf("allocate host callback payload")
		}
		defer C.free(cPayload)
		requestPtr = (*C.uint8_t)(cPayload)
	}
	callCode := C.call_host_api(cMethod, requestPtr, C.size_t(len(rawPayload)), &response)
	var rawResponse []byte
	if response.ptr != nil && response.len > 0 {
		rawResponse = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.free_host_buffer(response.ptr, response.len)
	}
	if len(rawResponse) == 0 {
		return nil, fmt.Errorf("host callback %s returned no response, code=%d", method, int(callCode))
	}
	var env envelope
	if err := json.Unmarshal(rawResponse, &env); err != nil {
		return nil, fmt.Errorf("decode host callback envelope %s: %w", method, err)
	}
	if !env.OK {
		if env.Error != nil {
			return nil, fmt.Errorf("%s: %s", env.Error.Code, env.Error.Message)
		}
		return nil, fmt.Errorf("host callback %s failed", method)
	}
	if callCode != 0 {
		return nil, fmt.Errorf("host callback %s returned code=%d", method, int(callCode))
	}
	return append(json.RawMessage(nil), env.Result...), nil
}

func hostLog(level, message string, fields map[string]any) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = callHost(ctx, methodHostLog, hostLogRequest{Level: level, Message: message, Fields: fields})
}

func okEnvelope(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

func parseClockTimes(values []string) ([]clockTime, error) {
	out := make([]clockTime, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(unquote(value))
		if value == "" {
			continue
		}
		parts := strings.Split(value, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid time %q, want HH:MM", value)
		}
		hour, errHour := strconv.Atoi(parts[0])
		minute, errMinute := strconv.Atoi(parts[1])
		if errHour != nil || errMinute != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
			return nil, fmt.Errorf("invalid time %q, want HH:MM", value)
		}
		raw := fmt.Sprintf("%02d:%02d", hour, minute)
		if _, exists := seen[raw]; exists {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, clockTime{Hour: hour, Minute: minute, Raw: raw})
	}
	return out, nil
}

func mustParseClockTimes(values []string) []clockTime {
	out, err := parseClockTimes(values)
	if err != nil {
		panic(err)
	}
	return out
}

func clockTimesToStrings(times []clockTime) []string {
	out := make([]string, 0, len(times))
	for _, t := range times {
		out = append(out, t.Raw)
	}
	return out
}

func stripYAMLComment(line string) string {
	inSingle := false
	inDouble := false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}

func countLeadingSpaces(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}

func splitYAMLKeyValue(line string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func normalizeKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
}

func parseInlineList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || value == "[]" {
		return nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
		if value == "" {
			return nil
		}
		parts := strings.Split(value, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			out = append(out, unquote(strings.TrimSpace(part)))
		}
		return out
	}
	return []string{unquote(value)}
}

func unquote(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func parseBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(unquote(value))) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	default:
		return false, false
	}
}

func parseInt(value string) (int, bool) {
	parsed, err := strconv.Atoi(strings.TrimSpace(unquote(value)))
	return parsed, err == nil
}

func headerGet(headers map[string][]string, key string) string {
	for header, values := range headers {
		if strings.EqualFold(header, key) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	return ""
}

func queryGet(values map[string][]string, key string) string {
	for k, items := range values {
		if strings.EqualFold(k, key) && len(items) > 0 {
			return strings.TrimSpace(items[0])
		}
	}
	return ""
}

func sessionID(slot, authID string) string {
	return "codex-window-keeper-" + strings.NewReplacer(" ", "-", ":", "").Replace(slot) + "-" + shortHash(authID)
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func truncateForLog(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

func mustLocation(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.Local
	}
	return loc
}
