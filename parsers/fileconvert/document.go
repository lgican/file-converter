// Package fileconvert handles document conversions using Pandoc.
package fileconvert

import (
	"bytes"
	"fmt"
	"os/exec"
)

type documentConverter struct{}

func init() {
	Register(&documentConverter{})
}

func (c *documentConverter) Name() string {
	return "Document Converter (Pandoc)"
}

func (c *documentConverter) SupportedFormats() []Format {
	return []Format{
		{Extension: ".docx", MimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Category: CategoryDocument, Name: "Word Document"},
		{Extension: ".odt", MimeType: "application/vnd.oasis.opendocument.text", Category: CategoryDocument, Name: "OpenDocument Text"},
		{Extension: ".rtf", MimeType: "application/rtf", Category: CategoryDocument, Name: "Rich Text Format"},
		{Extension: ".txt", MimeType: "text/plain", Category: CategoryDocument, Name: "Plain Text"},
		{Extension: ".md", MimeType: "text/markdown", Category: CategoryDocument, Name: "Markdown"},
		{Extension: ".html", MimeType: "text/html", Category: CategoryDocument, Name: "HTML"},
		{Extension: ".epub", MimeType: "application/epub+zip", Category: CategoryDocument, Name: "EPUB"},
		{Extension: ".pdf", MimeType: "application/pdf", Category: CategoryDocument, Name: "PDF"},
		{Extension: ".tex", MimeType: "application/x-tex", Category: CategoryDocument, Name: "LaTeX"},
		{Extension: ".rst", MimeType: "text/x-rst", Category: CategoryDocument, Name: "reStructuredText"},
		{Extension: ".json", MimeType: "application/json", Category: CategoryDocument, Name: "JSON"},
		{Extension: ".csv", MimeType: "text/csv", Category: CategoryDocument, Name: "CSV"},
		{Extension: ".tsv", MimeType: "text/tab-separated-values", Category: CategoryDocument, Name: "TSV"},
		{Extension: ".xml", MimeType: "application/xml", Category: CategoryDocument, Name: "XML"},
	}
}

func (c *documentConverter) CanConvert(from, to string) bool {
	from = normalizeExt(from)
	to = normalizeExt(to)

	// Check if Pandoc is available (bundled or system)
	if !isCommandAvailable("pandoc") {
		return false
	}

	// Pandoc cannot read PDF as input — handled by pdf.go instead
	if from == ".pdf" {
		return false
	}

	// Pandoc cannot produce PDF without a PDF engine (wkhtmltopdf/LaTeX)
	if to == ".pdf" {
		return false
	}

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

	return hasFrom && hasTo && from != to
}

func (c *documentConverter) Convert(req ConversionRequest) (*ConversionResult, error) {
	from := normalizeExt(req.FromFormat)
	to := normalizeExt(req.ToFormat)

	// Map extensions to Pandoc format names (input vs output differ for some formats)
	fromFormat := getPandocInputFormat(from)
	toFormat := getPandocOutputFormat(to)

	// Build Pandoc command
	args := []string{
		"-f", fromFormat,
		"-t", toFormat,
		"-o", "-", // Write to stdout
	}

	// Execute Pandoc with data piped through stdin/stdout
	pandocPath, _ := findBinary("pandoc")
	cmd := exec.Command(pandocPath, args...)
	cmd.Stdin = bytes.NewReader(req.Data)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pandoc conversion failed: %w (stderr: %s)", err, stderr.String())
	}

	// Determine MIME type
	mimeType := getDocumentMimeType(to)

	return &ConversionResult{
		Data:     stdout.Bytes(),
		MimeType: mimeType,
	}, nil
}

func getPandocInputFormat(ext string) string {
	formats := map[string]string{
		".docx": "docx",
		".odt":  "odt",
		".rtf":  "rtf",
		".txt":  "markdown",
		".md":   "markdown",
		".html": "html",
		".epub": "epub",
		".tex":  "latex",
		".rst":  "rst",
		".json": "json",
		".csv":  "csv",
		".tsv":  "tsv",
		".xml":  "docbook",
	}

	if format, ok := formats[ext]; ok {
		return format
	}
	return ext[1:] // Remove dot
}

func getPandocOutputFormat(ext string) string {
	formats := map[string]string{
		".docx": "docx",
		".odt":  "odt",
		".rtf":  "rtf",
		".txt":  "plain",
		".md":   "markdown",
		".html": "html",
		".epub": "epub",
		".tex":  "latex",
		".rst":  "rst",
		".json": "json",
		".csv":  "csv",
		".tsv":  "tsv",
		".xml":  "docbook",
	}

	if format, ok := formats[ext]; ok {
		return format
	}
	return ext[1:] // Remove dot
}

func getDocumentMimeType(ext string) string {
	mimeTypes := map[string]string{
		".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".doc":  "application/msword",
		".odt":  "application/vnd.oasis.opendocument.text",
		".rtf":  "application/rtf",
		".txt":  "text/plain",
		".md":   "text/markdown",
		".html": "text/html",
		".epub": "application/epub+zip",
		".pdf":  "application/pdf",
		".tex":  "application/x-tex",
		".rst":  "text/x-rst",
		".json": "application/json",
		".csv":  "text/csv",
		".tsv":  "text/tab-separated-values",
		".xml":  "application/xml",
	}

	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}
