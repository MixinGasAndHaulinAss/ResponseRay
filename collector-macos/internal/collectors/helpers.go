package collectors

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), errors.New(strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func writeText(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), 0o644)
}

func userHomes() []string {
	var homes []string
	usersDir := "/Users"
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return homes
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "Shared" || strings.HasPrefix(name, ".") {
			continue
		}
		homes = append(homes, filepath.Join(usersDir, name))
	}
	return homes
}

func usernameFromHome(home string) string {
	return filepath.Base(home)
}

func walkSafe(root string, predicate func(path string, info fs.FileInfo) bool, action func(path string, info fs.FileInfo)) {
	if _, err := os.Stat(root); err != nil {
		return
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, ferr := d.Info()
		if ferr != nil {
			return nil
		}
		if predicate != nil && !predicate(path, info) {
			return nil
		}
		action(path, info)
		return nil
	})
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	return lines, s.Err()
}
