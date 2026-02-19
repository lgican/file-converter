// Package fileconvert implements the file conversion format handler.
// It is automatically registered with the formats registry on import.
package fileconvert

import (
	"github.com/lgican/File-Converter/formats"
	parser "github.com/lgican/File-Converter/parsers/fileconvert"
)

func init() {
	formats.Register(&converter{})
}

type converter struct{}

func (c *converter) Name() string {
	return "File Converter"
}

func (c *converter) Extensions() []string {
	// Return common extensions - actual detection happens via Match
	return []string{
		// Images (basic + advanced)
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".tif",
		".ico", ".svg", ".avif", ".jxl", ".heic", ".heif", ".psd", ".eps",
		".ai", ".xcf", ".cr2", ".cr3", ".nef", ".arw", ".dng", ".orf",
		".rw2", ".raf", ".raw",
		// Audio
		".mp3", ".wav", ".flac", ".ogg", ".oga", ".opus", ".aac", ".alac",
		".m4a", ".wma", ".amr", ".ac3", ".aiff", ".aif", ".mp2", ".au",
		".m4b", ".voc", ".weba",
		// Video
		".mkv", ".mp4", ".webm", ".avi", ".mov", ".wmv", ".mpg", ".mpeg",
		".flv", ".f4v", ".vob", ".m4v", ".3gp", ".3g2", ".mxf", ".ogv",
		".ts", ".mts", ".m2ts", ".h264", ".divx", ".swf", ".amv", ".asf",
		// Documents & Spreadsheets
		".docx", ".doc", ".pptx", ".xlsx", ".odt", ".rtf", ".txt", ".md",
		".html", ".epub", ".pdf", ".tex", ".rst", ".json", ".csv", ".tsv", ".xml",
	}
}

func (c *converter) Match(data []byte) bool {
	// This converter is triggered explicitly via API, not auto-detection
	// Return false so it doesn't interfere with other converters
	return false
}

func (c *converter) Convert(data []byte) ([]formats.ConvertedFile, error) {
	// This converter is used via the API endpoint, not directly
	// The API endpoint handles the conversion request with format parameters
	return nil, nil
}

// GetSupportedFormats returns all formats grouped by category for the API.
func GetSupportedFormats() map[parser.FormatCategory][]parser.Format {
	return parser.GetAllFormats()
}

// ConvertFile performs a file conversion with the specified parameters.
func ConvertFile(data []byte, fromFormat, toFormat string, quality int) (*parser.ConversionResult, error) {
	conv := parser.GetConverter(fromFormat, toFormat)
	if conv == nil {
		return nil, parser.ErrUnsupportedConversion
	}

	req := parser.ConversionRequest{
		Data:       data,
		FromFormat: fromFormat,
		ToFormat:   toFormat,
		Quality:    quality,
	}

	return conv.Convert(req)
}
