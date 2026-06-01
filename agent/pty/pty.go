package pty

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chenhg5/cc-connect/core"
	gopty "github.com/creack/pty"
)

func init() {
	core.RegisterAgent("pty", newAgent)
}

// Strips ANSI/VT escapes. The first branch is a full CSI matcher:
// ESC [ , parameter bytes (0x30-0x3F, includes digits ; and the private-mode
// ? < = >), intermediate bytes (0x20-0x2F), then a final byte (0x40-0x7E).
// This catches private-mode toggles like bracketed paste (ESC[?2004h/l),
// cursor hide (ESC[?25l) and alt-screen (ESC[?1049h) that a digits-only
// pattern would miss.
var ansiRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|\x1b[^[\]()].?`)

func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

// --- Agent ---

type agent struct {
	mu      sync.RWMutex
	workDir string
	shell   string
	timeout time.Duration
	env     []string
}

// defaultCommandTimeout is how long Send waits for a command to finish before
// returning a soft "done" while leaving the underlying process running.
const defaultCommandTimeout = 120 * time.Second

// parseTimeout reads the per-command timeout from config options. Accepts a
// plain number of seconds (int64/float64 from TOML) or a Go duration string
// like "30m". Falls back to defaultCommandTimeout on missing/invalid input.
func parseTimeout(v any) time.Duration {
	switch t := v.(type) {
	case int64:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
	case float64:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
	case string:
		if d, err := time.ParseDuration(t); err == nil && d > 0 {
			return d
		}
	}
	return defaultCommandTimeout
}

func newAgent(opts map[string]any) (core.Agent, error) {
	workDir, _ := opts["work_dir"].(string)
	if workDir == "" {
		workDir, _ = os.Getwd()
	}
	shell, _ := opts["shell"].(string)
	if shell == "" {
		shell = detectShell()
	}
	timeout := parseTimeout(opts["command_timeout"])
	return &agent{workDir: workDir, shell: shell, timeout: timeout}, nil
}

func detectShell() string {
	if runtime.GOOS == "windows" {
		return "cmd.exe"
	}
	for _, sh := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(sh); err == nil {
			return sh
		}
	}
	return "/bin/sh"
}

func (a *agent) Name() string { return "pty" }

func (a *agent) StartSession(ctx context.Context, sessionID string) (core.AgentSession, error) {
	a.mu.RLock()
	workDir := a.workDir
	shell := a.shell
	timeout := a.timeout
	env := append([]string{}, a.env...)
	a.mu.RUnlock()
	return newSession(ctx, workDir, shell, env, timeout, sessionID)
}

func (a *agent) ListSessions(_ context.Context) ([]core.AgentSessionInfo, error) {
	return nil, nil
}

func (a *agent) Stop() error { return nil }

func (a *agent) SetSessionEnv(env []string) {
	a.mu.Lock()
	a.env = env
	a.mu.Unlock()
}

func (a *agent) SetWorkDir(dir string) {
	a.mu.Lock()
	a.workDir = dir
	a.mu.Unlock()
}

func (a *agent) GetWorkDir() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.workDir
}

// --- Session ---

type session struct {
	sessionID string
	ptyFile   *os.File
	cmd       *exec.Cmd
	events    chan core.Event
	alive     atomic.Bool
	cancel    context.CancelFunc
	ctx       context.Context
	timeout   time.Duration

	mu          sync.Mutex
	shellPrompt string
	cmdDone     chan struct{}
	cmdActive   bool
	isFirst     bool
}

func newSession(parentCtx context.Context, workDir, shell string, extraEnv []string, timeout time.Duration, sessionID string) (*session, error) {
	ctx, cancel := context.WithCancel(parentCtx)
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}

	cmd := exec.CommandContext(ctx, shell, "-l")
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Env = append(cmd.Env, "TERM=xterm-256color", "LANG=en_US.UTF-8")

	ptmx, err := gopty.StartWithSize(cmd, &gopty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("pty: start shell: %w", err)
	}

	s := &session{
		sessionID: sessionID,
		ptyFile:   ptmx,
		cmd:       cmd,
		events:    make(chan core.Event, 64),
		cancel:    cancel,
		ctx:       ctx,
		timeout:   timeout,
		isFirst:   true,
	}
	s.alive.Store(true)

	go s.readLoop()
	go s.waitExit()

	slog.Info("pty: session started", "session", sessionID, "shell", shell, "cwd", workDir)
	return s, nil
}

func (s *session) waitExit() {
	err := s.cmd.Wait()
	s.alive.Store(false)
	if err != nil {
		slog.Debug("pty: shell exited", "error", err)
	}
	s.emit(core.Event{Type: core.EventText, Content: "```\nshell exited\n```"})
	s.emit(core.Event{Type: core.EventResult, Done: true})
}

func (s *session) readLoop() {
	rawCh := make(chan []byte, 64)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := s.ptyFile.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case rawCh <- data:
				case <-s.ctx.Done():
					return
				}
			}
			if err != nil {
				close(rawCh)
				return
			}
		}
	}()

	var accum []byte
	flush := func() {
		if len(accum) == 0 {
			return
		}
		s.processOutput(accum)
		accum = accum[:0]
	}

	for {
		if len(accum) > 0 {
			select {
			case data, ok := <-rawCh:
				if !ok {
					flush()
					return
				}
				accum = append(accum, data...)
				if len(accum) >= 4096 {
					flush()
				}
			case <-time.After(100 * time.Millisecond):
				flush()
			case <-s.ctx.Done():
				return
			}
		} else {
			select {
			case data, ok := <-rawCh:
				if !ok {
					return
				}
				accum = append(accum, data...)
			case <-s.ctx.Done():
				return
			}
		}
	}
}

func (s *session) processOutput(raw []byte) {
	text := stripANSI(string(raw))
	if strings.TrimSpace(text) == "" {
		return
	}

	s.mu.Lock()
	if s.isFirst {
		s.shellPrompt = strings.TrimSpace(text)
		s.isFirst = false
		s.mu.Unlock()
		slog.Debug("pty: captured shell prompt", "prompt", s.shellPrompt)
		return
	}
	cmdActive := s.cmdActive
	cmdDone := s.cmdDone
	prompt := s.shellPrompt
	s.mu.Unlock()

	wrapped := fmt.Sprintf("```\n%s\n```", strings.TrimRight(text, " \t\r\n"))
	s.emit(core.Event{Type: core.EventText, Content: wrapped})

	if cmdActive && prompt != "" && strings.HasSuffix(strings.TrimSpace(text), prompt) {
		s.emit(core.Event{Type: core.EventResult, Done: true})
		select {
		case cmdDone <- struct{}{}:
		default:
		}
	}
}

func (s *session) emit(ev core.Event) {
	select {
	case s.events <- ev:
	case <-s.ctx.Done():
	}
}

func (s *session) Send(prompt string, _ []core.ImageAttachment, _ []core.FileAttachment) error {
	if !s.alive.Load() {
		return fmt.Errorf("pty: session not alive")
	}

	trimmed := strings.TrimSpace(prompt)

	if strings.EqualFold(trimmed, "@term stop") {
		s.emit(core.Event{Type: core.EventText, Content: "```\nshell terminated\n```"})
		s.emit(core.Event{Type: core.EventResult, Done: true})
		go s.Close()
		return nil
	}
	if strings.EqualFold(trimmed, "@term ctrl-c") {
		if s.cmd.Process != nil {
			s.cmd.Process.Signal(os.Interrupt)
		}
		s.emit(core.Event{Type: core.EventText, Content: "```\nSIGINT sent\n```"})
		s.emit(core.Event{Type: core.EventResult, Done: true})
		return nil
	}

	done := make(chan struct{}, 1)
	s.mu.Lock()
	s.cmdActive = true
	s.cmdDone = done
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.cmdActive = false
		s.cmdDone = nil
		s.mu.Unlock()
	}()

	if _, err := s.ptyFile.Write([]byte(prompt + "\n")); err != nil {
		return fmt.Errorf("pty: write: %w", err)
	}

	select {
	case <-done:
		return nil
	case <-time.After(s.timeout):
		slog.Warn("pty: command soft timeout", "session", s.sessionID, "timeout", s.timeout)
		s.emit(core.Event{Type: core.EventResult, Done: true})
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *session) RespondPermission(_ string, _ core.PermissionResult) error {
	return nil
}

func (s *session) Events() <-chan core.Event { return s.events }

func (s *session) CurrentSessionID() string { return s.sessionID }

func (s *session) Alive() bool { return s.alive.Load() }

func (s *session) Close() error {
	s.cancel()
	if s.ptyFile != nil {
		s.ptyFile.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
	}
	s.alive.Store(false)
	return nil
}
