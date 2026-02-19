// Package fileconvert handles finding bundled or system binaries.
package fileconvert

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// findBinary searches for an executable in the following order:
// 1. ./bin/ directory relative to the executable (bundled with app for portability)
// 2. ./bin/ directory relative to the current working directory (for go run)
// 3. System PATH
func findBinary(name string) (string, bool) {
	// Add .exe extension on Windows
	if runtime.GOOS == "windows" && filepath.Ext(name) != ".exe" {
		name = name + ".exe"
	}

	// Try bundled binary relative to executable first (for compiled binary)
	execPath, err := os.Executable()
	if err == nil {
		binDir := filepath.Join(filepath.Dir(execPath), "bin")
		bundledPath := filepath.Join(binDir, name)
		if _, err := os.Stat(bundledPath); err == nil {
			return bundledPath, true
		}
	}

	// Try bundled binary relative to current working directory (for go run)
	cwd, err := os.Getwd()
	if err == nil {
		cwdBinPath := filepath.Join(cwd, "bin", name)
		if _, err := os.Stat(cwdBinPath); err == nil {
			return cwdBinPath, true
		}
	}

	// Fall back to system PATH
	systemPath, err := exec.LookPath(name)
	if err == nil {
		return systemPath, true
	}

	return "", false
}

// isCommandAvailable checks if a command is available (bundled or system).
func isCommandAvailable(name string) bool {
	_, found := findBinary(name)
	return found
}
