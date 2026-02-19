package fileconvert

import (
	"bytes"
	"fmt"
	"os/exec"
)

func init() {
	Register(&ffmpegConverter{})
}

type ffmpegConverter struct{}

func (c *ffmpegConverter) Name() string {
	return "FFmpeg Converter"
}

func (c *ffmpegConverter) SupportedFormats() []Format {
	return []Format{
		// Audio formats
		{Extension: ".mp3", MimeType: "audio/mpeg", Category: CategoryAudio, Name: "MP3", CanConvert: []string{".wav", ".flac", ".ogg", ".m4a", ".aac"}},
		{Extension: ".wav", MimeType: "audio/wav", Category: CategoryAudio, Name: "WAV", CanConvert: []string{".mp3", ".flac", ".ogg", ".m4a", ".aac"}},
		{Extension: ".flac", MimeType: "audio/flac", Category: CategoryAudio, Name: "FLAC", CanConvert: []string{".mp3", ".wav", ".ogg", ".m4a", ".aac"}},
		{Extension: ".ogg", MimeType: "audio/ogg", Category: CategoryAudio, Name: "OGG", CanConvert: []string{".mp3", ".wav", ".flac", ".m4a", ".aac"}},
		{Extension: ".m4a", MimeType: "audio/mp4", Category: CategoryAudio, Name: "M4A", CanConvert: []string{".mp3", ".wav", ".flac", ".ogg", ".aac"}},
		{Extension: ".aac", MimeType: "audio/aac", Category: CategoryAudio, Name: "AAC", CanConvert: []string{".mp3", ".wav", ".flac", ".ogg", ".m4a"}},

		// Video formats
		{Extension: ".mp4", MimeType: "video/mp4", Category: CategoryVideo, Name: "MP4", CanConvert: []string{".webm", ".mkv", ".avi", ".mov", ".gif"}},
		{Extension: ".webm", MimeType: "video/webm", Category: CategoryVideo, Name: "WebM", CanConvert: []string{".mp4", ".mkv", ".avi", ".mov", ".gif"}},
		{Extension: ".mkv", MimeType: "video/x-matroska", Category: CategoryVideo, Name: "MKV", CanConvert: []string{".mp4", ".webm", ".avi", ".mov"}},
		{Extension: ".avi", MimeType: "video/x-msvideo", Category: CategoryVideo, Name: "AVI", CanConvert: []string{".mp4", ".webm", ".mkv", ".mov"}},
		{Extension: ".mov", MimeType: "video/quicktime", Category: CategoryVideo, Name: "MOV", CanConvert: []string{".mp4", ".webm", ".mkv", ".avi"}},
	}
}

func (c *ffmpegConverter) CanConvert(from, to string) bool {
	from = normalizeExt(from)
	to = normalizeExt(to)

	for _, f := range c.SupportedFormats() {
		if f.Extension == from {
			for _, target := range f.CanConvert {
				if target == to {
					return true
				}
			}
		}
	}
	return false
}

func (c *ffmpegConverter) Convert(req ConversionRequest) (*ConversionResult, error) {
	to := normalizeExt(req.ToFormat)

	// Determine output format for FFmpeg
	outputFormat := to[1:] // Remove leading dot

	// Build FFmpeg command
	// Input from stdin (pipe:0), output to stdout (pipe:1)
	args := []string{
		"-i", "pipe:0", // Read from stdin
		"-f", outputFormat, // Output format
	}

	// Add quality/codec settings based on output format
	switch to {
	case ".mp3":
		args = append(args, "-acodec", "libmp3lame", "-q:a", fmt.Sprintf("%d", getAudioQuality(req.Quality)))
	case ".wav":
		args = append(args, "-acodec", "pcm_s16le")
	case ".flac":
		args = append(args, "-acodec", "flac")
	case ".ogg":
		args = append(args, "-acodec", "libvorbis", "-q:a", fmt.Sprintf("%d", getAudioQuality(req.Quality)))
	case ".aac", ".m4a":
		args = append(args, "-acodec", "aac", "-b:a", "192k")
	case ".mp4":
		args = append(args, "-vcodec", "libx264", "-crf", fmt.Sprintf("%d", getVideoCRF(req.Quality)), "-acodec", "aac")
	case ".webm":
		args = append(args, "-vcodec", "libvpx-vp9", "-crf", fmt.Sprintf("%d", getVideoCRF(req.Quality)), "-acodec", "libopus")
	case ".mkv":
		args = append(args, "-vcodec", "libx264", "-crf", fmt.Sprintf("%d", getVideoCRF(req.Quality)), "-acodec", "aac")
	case ".avi":
		args = append(args, "-vcodec", "mpeg4", "-q:v", "5", "-acodec", "mp3")
	case ".mov":
		args = append(args, "-vcodec", "libx264", "-crf", fmt.Sprintf("%d", getVideoCRF(req.Quality)), "-acodec", "aac")
	}

	args = append(args, "pipe:1") // Write to stdout

	// Execute FFmpeg with data piped through stdin/stdout (no temp files)
	ffmpegPath, _ := findBinary("ffmpeg")
	cmd := exec.Command(ffmpegPath, args...)
	cmd.Stdin = bytes.NewReader(req.Data)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg conversion failed: %w (stderr: %s)", err, stderr.String())
	}

	// Determine MIME type
	mimeType := getMimeType(to)

	return &ConversionResult{
		Data:     stdout.Bytes(),
		MimeType: mimeType,
	}, nil
}

// getAudioQuality converts quality (0-100) to FFmpeg audio quality (0-9, lower is better).
func getAudioQuality(quality int) int {
	if quality == 0 {
		return 2 // Default good quality
	}
	// Map 100-0 to 0-9
	return 9 - (quality * 9 / 100)
}

// getVideoCRF converts quality (0-100) to FFmpeg CRF (0-51, lower is better).
func getVideoCRF(quality int) int {
	if quality == 0 {
		return 23 // Default
	}
	// Map 100-0 to 18-28 (reasonable range)
	return 28 - (quality * 10 / 100)
}

func getMimeType(ext string) string {
	mimeTypes := map[string]string{
		".mp3":  "audio/mpeg",
		".wav":  "audio/wav",
		".flac": "audio/flac",
		".ogg":  "audio/ogg",
		".m4a":  "audio/mp4",
		".aac":  "audio/aac",
		".mp4":  "video/mp4",
		".webm": "video/webm",
		".mkv":  "video/x-matroska",
		".avi":  "video/x-msvideo",
		".mov":  "video/quicktime",
	}
	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}
