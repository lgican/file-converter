// Package fileconvert handles conversions between different file formats.
// All conversions are done in-memory without writing temporary files to disk.
package fileconvert

import (
	"fmt"
	"strings"
)

// FormatCategory represents the type of file format.
type FormatCategory string

const (
	CategoryImage    FormatCategory = "image"
	CategoryAudio    FormatCategory = "audio"
	CategoryVideo    FormatCategory = "video"
	CategoryDocument FormatCategory = "document"
)

// Format represents a file format that can be converted.
type Format struct {
	Extension  string // e.g., ".png", ".jpg"
	MimeType   string // e.g., "image/png"
	Category   FormatCategory
	Name       string   // Human-readable name
	CanConvert []string // Extensions this format can convert to
}

// ConversionRequest describes a file conversion operation.
type ConversionRequest struct {
	Data       []byte // Input file data
	FromFormat string // Source extension (e.g., ".png")
	ToFormat   string // Target extension (e.g., ".jpg")
	Quality    int    // Quality setting (1-100), 0 means default
}

// ConversionResult contains the converted file data.
type ConversionResult struct {
	Data     []byte // Output file data
	MimeType string // MIME type of output
}

// Converter is the interface for format converters.
type Converter interface {
	// Name returns the converter name.
	Name() string

	// SupportedFormats returns all formats this converter can handle.
	SupportedFormats() []Format

	// CanConvert returns true if this converter can handle the conversion.
	CanConvert(from, to string) bool

	// Convert performs the conversion in memory.
	Convert(req ConversionRequest) (*ConversionResult, error)
}

// Registry holds all registered converters.
var registry []Converter

// Register adds a converter to the global registry.
func Register(c Converter) {
	registry = append(registry, c)
}

// GetConverter finds a converter that can handle the requested conversion.
func GetConverter(from, to string) Converter {
	from = normalizeExt(from)
	to = normalizeExt(to)

	for _, c := range registry {
		if c.CanConvert(from, to) {
			return c
		}
	}
	return nil
}

// GetAllFormats returns all supported formats grouped by category.
func GetAllFormats() map[FormatCategory][]Format {
	result := make(map[FormatCategory][]Format)
	seen := make(map[string]bool)

	for _, c := range registry {
		for _, f := range c.SupportedFormats() {
			key := string(f.Category) + f.Extension
			if !seen[key] {
				result[f.Category] = append(result[f.Category], f)
				seen[key] = true
			}
		}
	}

	return result
}

// normalizeExt ensures extension has a leading dot and is lowercase.
func normalizeExt(ext string) string {
	ext = strings.ToLower(strings.TrimSpace(ext))
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return ext
}

// DetectFormat attempts to detect the format from file data.
func DetectFormat(data []byte) string {
	if len(data) < 16 {
		return ""
	}

	// Check magic bytes
	if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return ".jpg"
	}
	if data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
		return ".png"
	}
	if data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 {
		return ".gif"
	}
	if data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 {
		if data[8] == 0x57 && data[9] == 0x45 && data[10] == 0x42 && data[11] == 0x50 {
			return ".webp"
		}
		if data[8] == 0x57 && data[9] == 0x41 && data[10] == 0x56 && data[11] == 0x45 {
			return ".wav"
		}
		return ".avi"
	}
	if data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00 {
		return ".tiff"
	}
	if data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A {
		return ".tiff"
	}
	if data[0] == 0x42 && data[1] == 0x4D {
		return ".bmp"
	}
	if len(data) >= 12 && data[4] == 0x66 && data[5] == 0x74 && data[6] == 0x79 && data[7] == 0x70 {
		return ".mp4"
	}
	if data[0] == 0x1A && data[1] == 0x45 && data[2] == 0xDF && data[3] == 0xA3 {
		return ".mkv"
	}
	if data[0] == 0x49 && data[1] == 0x44 && data[2] == 0x33 {
		return ".mp3"
	}
	if data[0] == 0x66 && data[1] == 0x4C && data[2] == 0x61 && data[3] == 0x43 {
		return ".flac"
	}
	if data[0] == 0x4F && data[1] == 0x67 && data[2] == 0x67 && data[3] == 0x53 {
		return ".ogg"
	}

	return ""
}

// DetectFormatFromData is an exported wrapper for DetectFormat.
func DetectFormatFromData(data []byte) string {
	return DetectFormat(data)
}

// DetectFormatFromFilename attempts to detect format from file extension.
func DetectFormatFromFilename(filename string) string {
	// Find the last dot
	lastDot := strings.LastIndex(filename, ".")
	if lastDot == -1 || lastDot == len(filename)-1 {
		return ""
	}

	ext := filename[lastDot:]
	return normalizeExt(ext)
}

// ErrUnsupportedConversion is returned when a conversion is not supported.
var ErrUnsupportedConversion = fmt.Errorf("unsupported conversion")

// ErrConversionFailed is returned when a conversion fails.
var ErrConversionFailed = fmt.Errorf("conversion failed")
