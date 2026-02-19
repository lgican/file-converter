// server.go implements the HTTP server, session management, rate limiting,
// HMAC-signed session tokens, and all API route handlers.

package main

import (
	"archive/zip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lgican/File-Converter/formats"
	fileconvertformat "github.com/lgican/File-Converter/formats/fileconvert"
	bankparser "github.com/lgican/File-Converter/parsers/bank"
	fileconvertparser "github.com/lgican/File-Converter/parsers/fileconvert"
	"github.com/lgican/File-Converter/web"
)

// session holds the extracted files for a single conversion.
type session struct {
	files   []extractedFile
	created time.Time
}

// extractedFile is a single file produced by conversion.
type extractedFile struct {
	Name string `json:"name"`
	Size int    `json:"size"`
	Type string `json:"type"`
	data []byte
}

// sessionStore manages in-memory conversion results.
type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*session
	done     chan struct{} // closed on shutdown to stop cleanup goroutine
}

// newSessionStore creates a session store and starts a background goroutine
// that evicts sessions older than 10 minutes.
func newSessionStore() *sessionStore {
	s := &sessionStore{
		sessions: make(map[string]*session),
		done:     make(chan struct{}),
	}
	go s.cleanup()
	return s
}

// create stores files under a new random session ID and returns the ID.
func (s *sessionStore) create(files []extractedFile) string {
	id := randomID()
	s.mu.Lock()
	s.sessions[id] = &session{files: files, created: time.Now()}
	s.mu.Unlock()
	return id
}

// get returns the session for the given ID, or nil if not found.
func (s *sessionStore) get(id string) *session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

// cleanup removes sessions older than 10 minutes.
func (s *sessionStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			for id, sess := range s.sessions {
				if time.Since(sess.created) > 10*time.Minute {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		case <-s.done:
			return
		}
	}
}

// stop signals the cleanup goroutine to exit.
func (s *sessionStore) stop() { close(s.done) }

// rateLimiter implements a simple token-bucket rate limiter.
type rateLimiter struct {
	tokens     int64 // current tokens (atomic)
	maxTokens  int64
	refillRate int64 // tokens added per second
	done       chan struct{}
}

// newRateLimiter creates a token-bucket rate limiter and starts a background
// goroutine that refills tokens once per second.
func newRateLimiter(maxTokens, refillRate int64) *rateLimiter {
	rl := &rateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		done:       make(chan struct{}),
	}
	go rl.refill()
	return rl
}

// refill adds tokens to the bucket once per second up to maxTokens.
func (rl *rateLimiter) refill() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cur := atomic.LoadInt64(&rl.tokens)
			next := cur + rl.refillRate
			if next > rl.maxTokens {
				next = rl.maxTokens
			}
			atomic.StoreInt64(&rl.tokens, next)
		case <-rl.done:
			return
		}
	}
}

// allow returns true if a token is available, consuming one.
func (rl *rateLimiter) allow() bool {
	for {
		cur := atomic.LoadInt64(&rl.tokens)
		if cur <= 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&rl.tokens, cur, cur-1) {
			return true
		}
	}
}

// stop signals the refill goroutine to exit.
func (rl *rateLimiter) stop() { close(rl.done) }

// randomID returns a cryptographically random 32-character hex string.
func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is unrecoverable -- log and exit cleanly
		// rather than panicking inside an HTTP handler.
		slog.Error("crypto/rand failed", "error", err)
		os.Exit(1)
	}
	return hex.EncodeToString(b)
}

// isHexString returns true if s contains only hex characters.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// clientFingerprint returns a SHA-256 hash of the client's User-Agent,
// used to bind sessions to a specific browser/device.
//
// Note: the IP address is intentionally excluded. On dual-stack networks
// (IPv4 + IPv6) and in Docker, the browser may connect via different
// addresses for different requests (e.g. fetch() vs <a> navigation),
// which would invalidate the session token and cause spurious 403 errors.
func clientFingerprint(r *http.Request) string {
	ua := r.Header.Get("User-Agent")
	slog.Debug("fingerprint inputs", "ua", ua, "path", r.URL.Path)
	h := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(h[:])
}

// signToken creates an HMAC-SHA256 signed session token.
// Format: {32-hex-id}.{64-hex-hmac}
// The HMAC covers the session ID and the client fingerprint, binding the
// token to the originating User-Agent.
func signToken(id, fingerprint string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "|" + fingerprint))
	return id + "." + hex.EncodeToString(mac.Sum(nil))
}

// verifyToken validates an HMAC-signed token against the requesting client's
// User-Agent fingerprint. Returns the raw session ID and true if valid.
func verifyToken(token, fingerprint string, key []byte) (string, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	id, sig := parts[0], parts[1]

	if len(id) != 32 || !isHexString(id) {
		return "", false
	}
	if len(sig) != 64 || !isHexString(sig) {
		return "", false
	}

	// Recompute expected HMAC.
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "|" + fingerprint))
	expected := mac.Sum(nil)

	actual, err := hex.DecodeString(sig)
	if err != nil {
		return "", false
	}

	if !hmac.Equal(expected, actual) {
		return "", false
	}
	return id, true
}

// cmdServe starts the web interface on the given port. If basePath is
// non-empty, all routes are served under that prefix (e.g. "/converter").
func cmdServe(port, basePath string) {
	basePath = normalizeBasePath(basePath)

	// Structured JSON logger for machine-readable, searchable logs.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	store := newSessionStore()
	limiter := newRateLimiter(10, 2)      // 10 burst, 2/sec refill (convert)
	fileLimiter := newRateLimiter(30, 10) // 30 burst, 10/sec refill (file access)

	// Generate per-instance HMAC key for session token signing.
	// Ephemeral: all sessions are invalidated on server restart.
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		slog.Error("failed to generate HMAC key", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	// Serve the main page from embedded static files.
	mux.HandleFunc("/robots.txt", handleRobots)
	mux.HandleFunc("/", handleIndex(basePath))
	mux.HandleFunc("/api/info", handleInfo)
	mux.HandleFunc("/api/convert", handleConvert(store, limiter, hmacKey))
	mux.HandleFunc("/api/bank/convert", handleBankConvert(store, limiter, hmacKey))
	mux.HandleFunc("/api/bank/templates", handleBankTemplates)
	mux.HandleFunc("/api/fileconvert/formats", handleFileConvertFormats)
	mux.HandleFunc("/api/fileconvert/convert", handleFileConvertConvert(store, limiter, hmacKey))
	mux.HandleFunc("/api/files/", handleFile(store, hmacKey, fileLimiter))
	mux.HandleFunc("/api/zip/", handleZip(store, hmacKey, fileLimiter))

	// Serve embedded static assets (CSS, JS) under /static/ with cache headers.
	staticContent, _ := fs.Sub(web.StaticFS, "static")
	mux.Handle("/static/", cacheHeaders(
		http.StripPrefix("/static/", http.FileServer(http.FS(staticContent))),
	))

	addr := ":" + port

	var handler http.Handler = requestLogger(securityHeaders(mux))
	if basePath != "" {
		// Wrap all routes under basePath using StripPrefix so the inner
		// mux still handles root-relative paths like /api/convert.
		root := http.NewServeMux()
		root.HandleFunc("/api/info", handleInfo) // root-level health endpoint for Docker
		root.Handle(basePath+"/", http.StripPrefix(basePath, handler))
		handler = root
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("server starting",
			"version", version,
			"addr", addr,
			"basePath", basePath,
			"url", "http://localhost"+addr+basePath+"/",
		)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("shutdown initiated", "timeout", "10s")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	store.stop()
	limiter.stop()
	fileLimiter.stop()
	slog.Info("server stopped")
}

// responseCapture wraps http.ResponseWriter to capture the status code.
type responseCapture struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code before delegating to the underlying writer.
func (rc *responseCapture) WriteHeader(code int) {
	rc.status = code
	rc.ResponseWriter.WriteHeader(code)
}

// requestLogger logs every HTTP request with method, path, status, and duration.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rc := &responseCapture{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rc, r)
		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rc.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

// securityHeaders wraps a handler with common security headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("X-DNS-Prefetch-Control", "off")
		// Prevent search engines from indexing, caching, or snippeting any
		// response. This is the HTTP-header equivalent of <meta name="robots">
		// and is respected by all major crawlers.
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
		next.ServeHTTP(w, r)
	})
}

// cacheHeaders adds long-lived cache headers for immutable embedded assets.
func cacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		next.ServeHTTP(w, r)
	})
}

// handleRobots serves a restrictive robots.txt that disallows all crawling.
func handleRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

// handleIndex returns a handler that serves the embedded HTML page, injecting
// a <base href> tag so all relative URLs resolve correctly under basePath.
func handleIndex(basePath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; "+
				"connect-src 'self'; img-src 'self' data:; base-uri 'self'; "+
				"form-action 'self'; frame-ancestors 'none'")
		data, err := web.StaticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		// Inject <base href> for subpath hosting and version query strings
		// for cache-busting static assets.
		baseHref := basePath + "/"
		html := strings.Replace(string(data),
			"<title>Converter</title>",
			"<base href=\""+baseHref+"\">\n<title>Converter</title>", 1)
		html = strings.ReplaceAll(html, "static/css/style.css", "static/css/style.css?v="+version)
		html = strings.ReplaceAll(html, "static/js/app.js", "static/js/app.js?v="+version)

		w.Write([]byte(html))
	}
}

// handleInfo returns the server version as JSON.
func handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"version": version})
}

// convertResponse is the JSON returned after a successful conversion.
type convertResponse struct {
	SessionToken string          `json:"sessionToken"`
	Files        []extractedFile `json:"files"`
}

// handleConvert processes an uploaded file, auto-detecting its format.
func handleConvert(store *sessionStore, limiter *rateLimiter, hmacKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		// Rate limit conversion requests.
		if !limiter.allow() {
			w.Header().Set("Retry-After", "1")
			slog.Warn("rate limit exceeded", "remote", r.RemoteAddr)
			jsonError(w, "Too many requests -- try again shortly", http.StatusTooManyRequests)
			return
		}

		// Limit upload to 50 MB.
		r.Body = http.MaxBytesReader(w, r.Body, 50<<20)

		file, header, err := r.FormFile("file")
		if err != nil {
			jsonError(w, "No file uploaded", http.StatusBadRequest)
			return
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			jsonError(w, "Failed to read file", http.StatusBadRequest)
			return
		}

		conv := formats.Detect(header.Filename, data)
		if conv == nil {
			jsonError(w, "Unsupported file format", http.StatusBadRequest)
			return
		}

		items, err := conv.Convert(data)
		if err != nil {
			jsonError(w, "Conversion failed: "+err.Error(), http.StatusBadRequest)
			return
		}

		if len(items) == 0 {
			jsonError(w, "No content found in file", http.StatusUnprocessableEntity)
			return
		}

		files := make([]extractedFile, len(items))
		for i, item := range items {
			files[i] = extractedFile{
				Name: item.Name,
				Size: len(item.Data),
				Type: guessType(item.Name),
				data: item.Data,
			}
		}

		sid := store.create(files)
		token := signToken(sid, clientFingerprint(r), hmacKey)

		slog.Info("conversion complete",
			"session", sid,
			"filename", header.Filename,
			"input_bytes", len(data),
			"output_files", len(files),
		)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		json.NewEncoder(w).Encode(convertResponse{
			SessionToken: token,
			Files:        files,
		})
	}
}

// handleFile serves a single extracted file by session token and filename.
func handleFile(store *sessionStore, hmacKey []byte, limiter *rateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Rate limit file access to slow enumeration attempts.
		if !limiter.allow() {
			w.Header().Set("Retry-After", "1")
			slog.Warn("file rate limit exceeded", "remote", r.RemoteAddr)
			jsonError(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		// Path: /api/files/{token}/{filename}
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/files/"), "/", 2)
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		token, name := parts[0], parts[1]

		// Verify HMAC-signed token against client User-Agent fingerprint.
		sid, ok := verifyToken(token, clientFingerprint(r), hmacKey)
		if !ok {
			slog.Warn("invalid session token",
				"remote", r.RemoteAddr,
				"path", r.URL.Path,
			)
			jsonError(w, "Forbidden", http.StatusForbidden)
			return
		}

		sess := store.get(sid)
		if sess == nil {
			jsonError(w, "Session expired or not found", http.StatusNotFound)
			return
		}

		for _, f := range sess.files {
			if f.Name == name {
				ct := contentType(f.Name, f.Type)
				w.Header().Set("Content-Type", ct)
				w.Header().Set("Content-Disposition", safeDisposition(f.Name))
				w.Header().Set("Cache-Control", "private, no-store")
				// Extracted HTML may contain malicious scripts;
				// block execution with a strict CSP.
				if f.Type == "html" {
					w.Header().Set("Content-Security-Policy",
						"default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'")
				}
				w.Write(f.data)
				return
			}
		}
		http.NotFound(w, r)
	}
}

// handleZip streams all extracted files as a zip archive directly to the client.
func handleZip(store *sessionStore, hmacKey []byte, limiter *rateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Rate limit zip downloads.
		if !limiter.allow() {
			w.Header().Set("Retry-After", "1")
			slog.Warn("zip rate limit exceeded", "remote", r.RemoteAddr)
			jsonError(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		token := strings.TrimPrefix(r.URL.Path, "/api/zip/")

		// Verify HMAC-signed token against client User-Agent fingerprint.
		sid, ok := verifyToken(token, clientFingerprint(r), hmacKey)
		if !ok {
			slog.Warn("invalid session token",
				"remote", r.RemoteAddr,
				"path", r.URL.Path,
			)
			jsonError(w, "Forbidden", http.StatusForbidden)
			return
		}

		sess := store.get(sid)
		if sess == nil {
			jsonError(w, "Session expired or not found", http.StatusNotFound)
			return
		}

		// Set headers before streaming -- cannot change after first write.
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="converted_output.zip"`)
		w.Header().Set("Cache-Control", "private, no-store")

		// Stream zip directly to the response writer (no buffering).
		zw := zip.NewWriter(w)
		for _, f := range sess.files {
			fw, err := zw.Create(f.Name)
			if err != nil {
				break
			}
			if _, err := fw.Write(f.data); err != nil {
				break
			}
		}
		zw.Close()
	}
}

// jsonError writes a JSON error response with the given message and HTTP status code.
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// guessType returns a short type category string based on file extension.
func guessType(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm"):
		return "html"
	case strings.HasSuffix(lower, ".txt"):
		return "text"
	case strings.HasSuffix(lower, ".rtf"):
		return "rtf"
	case strings.HasSuffix(lower, ".png"):
		return "image"
	case strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".jpeg"):
		return "image"
	case strings.HasSuffix(lower, ".gif"):
		return "image"
	case strings.HasSuffix(lower, ".pdf"):
		return "pdf"
	case strings.HasSuffix(lower, ".doc") || strings.HasSuffix(lower, ".docx"):
		return "document"
	case strings.HasSuffix(lower, ".xls") || strings.HasSuffix(lower, ".xlsx"):
		return "spreadsheet"
	default:
		return "file"
	}
}

// contentType maps a type category from guessType to a MIME content type.
func contentType(name, fileType string) string {
	switch fileType {
	case "html":
		return "text/html; charset=utf-8"
	case "text":
		return "text/plain; charset=utf-8"
	case "rtf":
		return "application/rtf"
	case "image":
		return imageMIME(name)
	case "pdf":
		return "application/pdf"
	default:
		return "application/octet-stream"
	}
}

// imageMIME returns the MIME type for an image file based on its extension.
func imageMIME(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(lower, ".gif"):
		return "image/gif"
	case strings.HasSuffix(lower, ".bmp"):
		return "image/bmp"
	case strings.HasSuffix(lower, ".webp"):
		return "image/webp"
	case strings.HasSuffix(lower, ".svg"):
		return "image/svg+xml"
	default:
		return "image/png"
	}
}

// safeDisposition returns a Content-Disposition header value with the
// filename sanitized to prevent header injection.
func safeDisposition(name string) string {
	safe := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	return fmt.Sprintf(`inline; filename="%s"`, safe)
}

// normalizeBasePath ensures basePath has a leading slash and no trailing
// slash. An empty string or "/" both mean root (no prefix needed).
func normalizeBasePath(s string) string {
	s = strings.TrimRight(s, "/")
	if s == "" {
		return ""
	}
	if s[0] != '/' {
		s = "/" + s
	}
	return s
}

// handleBankTemplates returns the list of available bank file templates.
func handleBankTemplates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	templates := bankparser.GetTemplateList()
	json.NewEncoder(w).Encode(templates)
}

// handleBankConvert processes CSV/Excel data and converts it to the selected output format.
func handleBankConvert(store *sessionStore, limiter *rateLimiter, hmacKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		// Rate limit conversion requests.
		if !limiter.allow() {
			w.Header().Set("Retry-After", "1")
			slog.Warn("rate limit exceeded", "remote", r.RemoteAddr)
			jsonError(w, "Too many requests -- try again shortly", http.StatusTooManyRequests)
			return
		}

		// Parse multipart form
		if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB limit
			jsonError(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		// Get template selection
		template := r.FormValue("template")
		if template == "" {
			template = "ACH_Payment" // default template
		}

		// Get output format (default: txt for fixed-width)
		outputFormat := r.FormValue("outputFormat")
		if outputFormat == "" {
			outputFormat = "txt"
		}

		// Get uploaded file
		file, header, err := r.FormFile("file")
		if err != nil {
			jsonError(w, "No file uploaded", http.StatusBadRequest)
			return
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			jsonError(w, "Failed to read file", http.StatusBadRequest)
			return
		}

		// Parse input (auto-detect CSV vs Excel)
		bankFile, err := bankparser.DecodeAuto(data, template)
		if err != nil {
			jsonError(w, "Failed to parse file: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Format output based on selected format
		var formatted []byte
		var outputName string
		var outputType string

		switch outputFormat {
		case "xlsx":
			formatted, err = bankFile.FormatAsExcel()
			if err != nil {
				jsonError(w, "Failed to create Excel output: "+err.Error(), http.StatusInternalServerError)
				return
			}
			outputName = template + "_formatted.xlsx"
			outputType = "spreadsheet"
		case "csv":
			formatted, err = bankFile.FormatAsCSV()
			if err != nil {
				jsonError(w, "Failed to create CSV output: "+err.Error(), http.StatusInternalServerError)
				return
			}
			outputName = template + "_formatted.csv"
			outputType = "text"
		default: // "txt" — fixed-width bank format
			formatted = bankFile.FormatAsFixedWidth()
			outputName = template + "_formatted.txt"
			outputType = "text"
		}

		// Determine original file name/type
		origName := header.Filename
		origType := "text"
		if strings.HasSuffix(strings.ToLower(origName), ".xlsx") || strings.HasSuffix(strings.ToLower(origName), ".xls") {
			origType = "spreadsheet"
		}

		// Create session with both original and formatted output
		files := []extractedFile{
			{
				Name: "original_" + origName,
				Size: len(data),
				Type: origType,
				data: data,
			},
			{
				Name: outputName,
				Size: len(formatted),
				Type: outputType,
				data: formatted,
			},
		}

		sid := store.create(files)
		token := signToken(sid, clientFingerprint(r), hmacKey)

		slog.Info("bank conversion complete",
			"session", sid,
			"filename", header.Filename,
			"template", template,
			"outputFormat", outputFormat,
			"input_bytes", len(data),
			"output_bytes", len(formatted),
		)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		json.NewEncoder(w).Encode(convertResponse{
			SessionToken: token,
			Files:        files,
		})
	}
}

// handleFileConvertFormats returns the list of supported file conversion formats.
func handleFileConvertFormats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	formats := fileconvertformat.GetSupportedFormats()
	json.NewEncoder(w).Encode(formats)
}

// handleFileConvertConvert processes a file conversion request.
func handleFileConvertConvert(store *sessionStore, limiter *rateLimiter, hmacKey []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		// Rate limit conversion requests.
		if !limiter.allow() {
			w.Header().Set("Retry-After", "1")
			slog.Warn("rate limit exceeded", "remote", r.RemoteAddr)
			jsonError(w, "Too many requests -- try again shortly", http.StatusTooManyRequests)
			return
		}

		// Parse multipart form - no size limit (all processed in RAM)
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			// If form is too large for initial buffer, that's OK - we'll stream it
			if err != http.ErrNotMultipart {
				// Continue anyway - we'll read the file directly
			}
		}

		// Get conversion parameters
		fromFormat := r.FormValue("from")
		toFormat := r.FormValue("to")
		qualityStr := r.FormValue("quality")

		if toFormat == "" {
			jsonError(w, "Missing output format", http.StatusBadRequest)
			return
		}

		quality := 90 // default
		if qualityStr != "" {
			if q, err := strconv.Atoi(qualityStr); err == nil {
				quality = q
			}
		}

		// Get uploaded file
		file, header, err := r.FormFile("file")
		if err != nil {
			jsonError(w, "No file uploaded", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Read file data into memory
		data, err := io.ReadAll(file)
		if err != nil {
			jsonError(w, "Failed to read file", http.StatusBadRequest)
			return
		}

		// Auto-detect input format if not provided
		if fromFormat == "" {
			fromFormat = fileconvertparser.DetectFormatFromData(data)
			if fromFormat == "" {
				// Try to detect from filename
				fromFormat = fileconvertparser.DetectFormatFromFilename(header.Filename)
			}
			if fromFormat == "" {
				// If we can't detect and no toFormat, just store the file
				if toFormat == "" {
					fromFormat = ".bin"
				} else {
					jsonError(w, "Could not detect input format - please specify", http.StatusBadRequest)
					return
				}
			}
			if fromFormat != ".bin" {
				slog.Info("auto-detected input format", "format", fromFormat, "filename", header.Filename)
			}
		}

		var files []extractedFile
		originalName := header.Filename

		// If no output format selected, just store the original file
		if toFormat == "" {
			files = []extractedFile{
				{
					Name: originalName,
					Size: len(data),
					Type: guessType(originalName),
					data: data,
				},
			}

			slog.Info("file uploaded without conversion", "filename", header.Filename, "bytes", len(data))
		} else {
			// Perform conversion (all in memory)
			result, err := fileconvertformat.ConvertFile(data, fromFormat, toFormat, quality)
			if err != nil {
				jsonError(w, "Conversion failed: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Create session with both original and converted file
			convertedName := strings.TrimSuffix(originalName, fromFormat) + toFormat

			files = []extractedFile{
				{
					Name: "original_" + originalName,
					Size: len(data),
					Type: guessType(originalName),
					data: data,
				},
				{
					Name: convertedName,
					Size: len(result.Data),
					Type: guessType(convertedName),
					data: result.Data,
				},
			}

			slog.Info("file conversion complete",
				"session", "",
				"filename", header.Filename,
				"from", fromFormat,
				"to", toFormat,
				"input_bytes", len(data),
				"output_bytes", len(result.Data),
			)
		}

		sid := store.create(files)
		token := signToken(sid, clientFingerprint(r), hmacKey)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		json.NewEncoder(w).Encode(convertResponse{
			SessionToken: token,
			Files:        files,
		})
	}
}
