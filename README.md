# File Converter

A multi-format file converter, bank file formatter, and email attachment
extractor — all in one self-contained web interface. All conversions happen
in memory with no temp files written to disk.

[![CI](https://github.com/lgican/File-Converter/actions/workflows/ci.yml/badge.svg)](https://github.com/lgican/File-Converter/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/lgican/File-Converter)](https://goreportcard.com/report/github.com/lgican/File-Converter)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Features

### File Converter
- **Image conversion** — PNG, JPEG, GIF, BMP, TIFF, WebP, ICO, SVG, HEIC, AVIF, and more (via ImageMagick)
- **Audio/Video conversion** — MP3, WAV, FLAC, OGG, AAC, MP4, MKV, AVI, WebM, MOV, and more (via FFmpeg)
- **Document conversion** — Markdown, DOCX, HTML, TXT, RTF, ODT, EPUB, and more (via Pandoc)
- **PDF text extraction** — pure Go, no external tools needed
- **Batch conversion** — queue multiple files and convert them all at once

### Bank File Formatter
- **Template-based formatting** — BeanStream_Detail (BMO), ACH_Payment, Wire_Transfer, Direct_Deposit
- **Auto-detect input** — reads both CSV and Excel (.xlsx) files
- **Multiple output formats** — fixed-width text (.txt), CSV (.csv), or Excel (.xlsx)
- **Column mapping and formatting** — fixed-width fields, padding, and trimming per template

### TNEF / Winmail.dat Extractor
- **Attachment extraction** — pull files from TNEF email attachments
- **LZFu RTF decompression** and HTML de-encapsulation from RTF
- **CID image resolution** — inline images converted to self-contained data URIs
- **External image embedding** — remote `<img>` sources fetched and inlined

### Platform
- **Modern web interface** — three-mode UI with drag-and-drop upload, file queues, and bulk download
- **Batteries included** — ImageMagick, FFmpeg, and Pandoc binaries are bundled in the `bin/` folder; no additional software needed
- **Pluggable format architecture** — add new formats without touching core code
- **Security hardened** — HMAC-signed session tokens, IP + device fingerprint binding, SSRF protection with DNS rebinding defense, rate limiting, strict CSP
- **Embedded web assets** — HTML, CSS, JS compiled into the binary via `go:embed`
- **Structured JSON logging** — `log/slog` with method, path, status, duration on every request

## Quick Start

### Prerequisites

- [Go](https://go.dev/) 1.25 or later

### Running the Server

From the project root, start the web server on port 8080:

```bash
go run ./cmd/converter serve
```

Then open [http://localhost:8080](http://localhost:8080) in your browser.

> **Troubleshooting:** If port 8080 is already in use, stop the existing
> process first or choose a different port. If `go` is not found, ensure
> Go is in your system PATH.

### Build

```bash
make build    # Build binary to bin/converter
make test     # Run tests with race detection
make vet      # Run go vet
make lint     # Run staticcheck
make check    # All of the above
make clean    # Remove bin/ and build artifacts
```

## Architecture

```
converter
├── bin/                 Bundled tool directories (committed to repo)
│   ├── ffmpeg/          FFmpeg executable + shared libraries
│   ├── imagemagick/     ImageMagick executable + DLLs
│   └── pandoc/          Pandoc executable
├── cmd/converter/       Web server entry point
├── cmd/inspect/         Low-level TNEF diagnostic tool
├── deploy/              Seccomp profile + deployment configs
├── formats/             Converter interface + registry
│   ├── bank/            Bank file format registration
│   ├── fileconvert/     File converter format registration
│   └── tnef/            TNEF format implementation
├── parsers/             Format-specific parsers
│   ├── bank/            CSV/Excel parsing, templates, fixed-width/CSV/XLSX output
│   ├── fileconvert/     Image, audio/video, document, PDF converters + binary discovery
│   └── tnef/            TNEF parser (MAPI, LZFu RTF, de-encapsulation)
└── web/                 Embedded static assets (go:embed)
    └── static/          HTML, CSS, JS served by the web UI
```

### Dependencies

- [excelize/v2](https://github.com/xuri/excelize) — Excel (.xlsx) read/write for bank file formatting
- [golang.org/x/image](https://pkg.go.dev/golang.org/x/image) — Extended image format support

### Bundled Tools

The following tools are already included in the `bin/` directory — no separate
installation required:

| Tool | Version | Used For |
|------|---------|----------|
| ImageMagick | 7.1.2 Q16-HDRI | Image format conversion |
| FFmpeg | Latest GPL shared | Audio/Video conversion |
| Pandoc | 3.9 | Document conversion |

### Pluggable Format System

Converter uses a registry pattern for format auto-detection:

1. **Magic bytes** — each format checks file headers first
2. **Extension fallback** — matches by file extension if magic bytes don't match
3. **Auto-registration** — formats register themselves via `init()`

### Adding a New Format

Create a package under `formats/` implementing the `Converter` interface:

```go
package myformat

import "github.com/lgican/File-Converter/formats"

func init() {
    formats.Register(&conv{})
}

type conv struct{}

func (c *conv) Name() string           { return "My Format" }
func (c *conv) Extensions() []string   { return []string{".myf"} }
func (c *conv) Match(data []byte) bool { return len(data) > 4 && data[0] == 0xAB }
func (c *conv) Convert(data []byte) ([]formats.ConvertedFile, error) {
    // Parse the format and return extracted files
    return nil, nil
}
```

Then add a blank import in `cmd/converter/main.go`:

```go
import _ "github.com/lgican/File-Converter/formats/myformat"
```

## Security

See [SECURITY.md](SECURITY.md) for the full security policy.

Key protections:

| Threat | Mitigation |
|--------|-----------|
| XSS in extracted HTML | Strict CSP: `'self'` for main page, `default-src 'none'` for extracted files |
| SSRF via image URLs | DNS rebinding-safe custom dialer, redirect validation, private IP blocks |
| Header injection | Control characters stripped from filenames |
| Upload abuse | 50 MB limit via `MaxBytesReader` + rate limiting |
| Session hijacking | HMAC-SHA256 signed tokens bound to client IP + User-Agent |
| Session enumeration | 128-bit `crypto/rand` session IDs + HMAC signature verification |
| File endpoint abuse | Separate rate limiter on `/api/files/` and `/api/zip/` |
| Slowloris / connection exhaustion | Read/Write/Idle timeouts + graceful shutdown |
| Clickjacking | `X-Frame-Options: DENY` + `frame-ancestors 'none'` |
| MIME sniffing | `X-Content-Type-Options: nosniff` |

### Logging

The web server emits structured JSON logs to stdout via Go's `log/slog`:

```json
{"time":"2026-02-13T12:00:00Z","level":"INFO","msg":"http request","method":"POST","path":"/api/convert","status":200,"duration_ms":42,"remote":"172.17.0.1:54321"}
{"time":"2026-02-13T12:00:00Z","level":"INFO","msg":"conversion complete","session":"abc123...","filename":"winmail.dat","input_bytes":196531,"output_files":5}
{"time":"2026-02-13T12:00:00Z","level":"WARN","msg":"invalid session token","remote":"10.0.0.5:12345","path":"/api/files/deadbeef.../body.html"}
```

### Session Security

Every conversion creates an **HMAC-SHA256 signed session token** that binds the
result to the originating client:

- **Token format**: `{128-bit-random-id}.{HMAC-SHA256-signature}`
- **HMAC key**: 256-bit, generated from `crypto/rand` at server startup (ephemeral)
- **Client fingerprint**: `SHA-256(client_ip | User-Agent)` — baked into the HMAC
- **Verification**: every file/zip request re-derives the fingerprint from the
  requesting client and validates the HMAC; mismatches return 403 Forbidden
- **Auto-expiry**: sessions are deleted after 10 minutes

## Free & Open Source

This project is released under the [MIT License](LICENSE) and is **completely
free to use**. Monetization of this software or derivative works is **strictly
prohibited**. This tool is built for the community and must remain freely
available to everyone.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE) — Copyright (c) 2026 Lancaster Group Inc.
