// Package fileconvert handles finding bundled or system binaries.
package fileconvert

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// findBinary searches for an executable in the following order:
//  1. ./bin/<tool>/ subdirectory relative to the executable (organised bundled layout)
//  2. ./bin/ directory relative to the executable (flat bundled layout)
//  3. ./bin/<tool>/ subdirectory relative to the working directory (for go run)
//  4. ./bin/ directory relative to the working directory (for go run)
//  5. System PATH
func findBinary(name string) (string, bool) {
	// Add .exe extension on Windows
	if runtime.GOOS == "windows" && filepath.Ext(name) != ".exe" {
		name = name + ".exe"
	}

	// Derive the subfolder name from the binary (e.g. "magick" → "imagemagick").
	sub := subfolderFor(strings.TrimSuffix(name, filepath.Ext(name)))

	// Try relative to the compiled executable first.
	if execPath, err := os.Executable(); err == nil {
		binDir := filepath.Join(filepath.Dir(execPath), "bin")
		if p := probe(binDir, sub, name); p != "" {
			return p, true
		}
	}

	// Try relative to the current working directory (covers `go run`).
	if cwd, err := os.Getwd(); err == nil {
		binDir := filepath.Join(cwd, "bin")
		if p := probe(binDir, sub, name); p != "" {
			return p, true
		}
	}

	// Fall back to system PATH
	systemPath, err := exec.LookPath(name)
	if err == nil {
		return systemPath, true
	}

	return "", false
}

// probe checks binDir/<sub>/<name> first, then binDir/<name>.
func probe(binDir, sub, name string) string {
	if sub != "" {
		p := filepath.Join(binDir, sub, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	p := filepath.Join(binDir, name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// subfolderFor maps a binary base name to its subdirectory under bin/.
func subfolderFor(base string) string {
	switch base {
	case "magick":
		return "imagemagick"
	case "ffmpeg":
		return "ffmpeg"
	case "pandoc":
		return "pandoc"
	case "pdftotext":
		return "poppler"
	default:
		return ""
	}
}

// isCommandAvailable checks if a command is available (bundled or system).
func isCommandAvailable(name string) bool {
	_, found := findBinary(name)
	return found
}
