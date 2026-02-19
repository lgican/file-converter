// Package fileconvert handles image conversions using ImageMagick.
package fileconvert

import (
	"bytes"
	"fmt"
	"os/exec"
)

type imagemagickConverter struct{}

func init() {
	Register(&imagemagickConverter{})
}

func (c *imagemagickConverter) Name() string {
	return "ImageMagick Converter"
}

func (c *imagemagickConverter) SupportedFormats() []Format {
	formats := []Format{
		// Common formats
		{Extension: ".png", MimeType: "image/png", Category: CategoryImage, Name: "PNG"},
		{Extension: ".jpg", MimeType: "image/jpeg", Category: CategoryImage, Name: "JPEG"},
		{Extension: ".jpeg", MimeType: "image/jpeg", Category: CategoryImage, Name: "JPEG"},
		{Extension: ".gif", MimeType: "image/gif", Category: CategoryImage, Name: "GIF"},
		{Extension: ".bmp", MimeType: "image/bmp", Category: CategoryImage, Name: "BMP"},
		{Extension: ".webp", MimeType: "image/webp", Category: CategoryImage, Name: "WebP"},
		{Extension: ".tiff", MimeType: "image/tiff", Category: CategoryImage, Name: "TIFF"},
		{Extension: ".tif", MimeType: "image/tiff", Category: CategoryImage, Name: "TIFF"},
		{Extension: ".ico", MimeType: "image/x-icon", Category: CategoryImage, Name: "ICO"},
		{Extension: ".svg", MimeType: "image/svg+xml", Category: CategoryImage, Name: "SVG"},

		// Advanced formats
		{Extension: ".avif", MimeType: "image/avif", Category: CategoryImage, Name: "AVIF"},
		{Extension: ".jxl", MimeType: "image/jxl", Category: CategoryImage, Name: "JPEG XL"},
		{Extension: ".heic", MimeType: "image/heic", Category: CategoryImage, Name: "HEIC"},
		{Extension: ".heif", MimeType: "image/heif", Category: CategoryImage, Name: "HEIF"},
		{Extension: ".psd", MimeType: "image/vnd.adobe.photoshop", Category: CategoryImage, Name: "PSD"},
		{Extension: ".eps", MimeType: "application/postscript", Category: CategoryImage, Name: "EPS"},
		{Extension: ".ai", MimeType: "application/postscript", Category: CategoryImage, Name: "AI"},
		{Extension: ".xcf", MimeType: "image/x-xcf", Category: CategoryImage, Name: "GIMP XCF"},

		// RAW formats
		{Extension: ".cr2", MimeType: "image/x-canon-cr2", Category: CategoryImage, Name: "Canon CR2"},
		{Extension: ".cr3", MimeType: "image/x-canon-cr3", Category: CategoryImage, Name: "Canon CR3"},
		{Extension: ".nef", MimeType: "image/x-nikon-nef", Category: CategoryImage, Name: "Nikon NEF"},
		{Extension: ".arw", MimeType: "image/x-sony-arw", Category: CategoryImage, Name: "Sony ARW"},
		{Extension: ".dng", MimeType: "image/x-adobe-dng", Category: CategoryImage, Name: "DNG"},
		{Extension: ".orf", MimeType: "image/x-olympus-orf", Category: CategoryImage, Name: "Olympus ORF"},
		{Extension: ".rw2", MimeType: "image/x-panasonic-rw2", Category: CategoryImage, Name: "Panasonic RW2"},
		{Extension: ".raf", MimeType: "image/x-fuji-raf", Category: CategoryImage, Name: "Fuji RAF"},
		{Extension: ".raw", MimeType: "image/x-raw", Category: CategoryImage, Name: "RAW"},
	}

	return formats
}

func (c *imagemagickConverter) CanConvert(from, to string) bool {
	from = normalizeExt(from)
	to = normalizeExt(to)

	// Check if ImageMagick is available (bundled or system)
	if !isCommandAvailable("magick") {
		return false
	}

	// ImageMagick can convert between most image formats
	supportedFormats := c.SupportedFormats()
	hasFrom, hasTo := false, false

	for _, f := range supportedFormats {
		if f.Extension == from {
			hasFrom = true
		}
		if f.Extension == to {
			hasTo = true
		}
	}

	return hasFrom && hasTo
}

func (c *imagemagickConverter) Convert(req ConversionRequest) (*ConversionResult, error) {
	from := normalizeExt(req.FromFormat)[1:] // Remove leading dot
	to := normalizeExt(req.ToFormat)[1:]

	// Build ImageMagick command
	args := []string{
		fmt.Sprintf("%s:-", from), // Read from stdin
	}

	// Add quality setting if applicable
	if req.Quality > 0 && (to == "jpg" || to == "jpeg" || to == "webp" || to == "avif") {
		args = append(args, "-quality", fmt.Sprintf("%d", req.Quality))
	}

	args = append(args, fmt.Sprintf("%s:-", to)) // Write to stdout

	// Execute ImageMagick with data piped through stdin/stdout (no temp files)
	magickPath, _ := findBinary("magick")
	cmd := exec.Command(magickPath, args...)
	cmd.Stdin = bytes.NewReader(req.Data)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("imagemagick conversion failed: %w (stderr: %s)", err, stderr.String())
	}

	// Determine MIME type
	mimeType := getMimeTypeForExt("." + to)

	return &ConversionResult{
		Data:     stdout.Bytes(),
		MimeType: mimeType,
	}, nil
}

func getMimeTypeForExt(ext string) string {
	mimeTypes := map[string]string{
		".png":  "image/png",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".gif":  "image/gif",
		".bmp":  "image/bmp",
		".webp": "image/webp",
		".tiff": "image/tiff",
		".tif":  "image/tiff",
		".ico":  "image/x-icon",
		".svg":  "image/svg+xml",
		".avif": "image/avif",
		".jxl":  "image/jxl",
		".heic": "image/heic",
		".heif": "image/heif",
		".psd":  "image/vnd.adobe.photoshop",
		".eps":  "application/postscript",
	}

	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}
