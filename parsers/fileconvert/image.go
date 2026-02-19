package fileconvert

import (
	"bytes"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"

	"golang.org/x/image/bmp"
	"golang.org/x/image/tiff"
	"golang.org/x/image/webp"
)

func init() {
	Register(&imageConverter{})
}

type imageConverter struct{}

func (c *imageConverter) Name() string {
	return "Image Converter"
}

func (c *imageConverter) SupportedFormats() []Format {
	return []Format{
		{Extension: ".png", MimeType: "image/png", Category: CategoryImage, Name: "PNG", CanConvert: []string{".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".webp"}},
		{Extension: ".jpg", MimeType: "image/jpeg", Category: CategoryImage, Name: "JPEG", CanConvert: []string{".png", ".bmp", ".gif", ".tiff", ".webp"}},
		{Extension: ".jpeg", MimeType: "image/jpeg", Category: CategoryImage, Name: "JPEG", CanConvert: []string{".png", ".bmp", ".gif", ".tiff", ".webp"}},
		{Extension: ".gif", MimeType: "image/gif", Category: CategoryImage, Name: "GIF", CanConvert: []string{".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"}},
		{Extension: ".bmp", MimeType: "image/bmp", Category: CategoryImage, Name: "BMP", CanConvert: []string{".png", ".jpg", ".jpeg", ".gif", ".tiff", ".webp"}},
		{Extension: ".webp", MimeType: "image/webp", Category: CategoryImage, Name: "WebP", CanConvert: []string{".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff"}},
		{Extension: ".tiff", MimeType: "image/tiff", Category: CategoryImage, Name: "TIFF", CanConvert: []string{".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}},
	}
}

func (c *imageConverter) CanConvert(from, to string) bool {
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

func (c *imageConverter) Convert(req ConversionRequest) (*ConversionResult, error) {
	from := normalizeExt(req.FromFormat)
	to := normalizeExt(req.ToFormat)

	// Decode source image
	img, err := c.decode(req.Data, from)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	// Encode to target format
	data, mimeType, err := c.encode(img, to, req.Quality)
	if err != nil {
		return nil, fmt.Errorf("failed to encode image: %w", err)
	}

	return &ConversionResult{
		Data:     data,
		MimeType: mimeType,
	}, nil
}

func (c *imageConverter) decode(data []byte, format string) (image.Image, error) {
	reader := bytes.NewReader(data)

	switch format {
	case ".png":
		return png.Decode(reader)
	case ".jpg", ".jpeg":
		return jpeg.Decode(reader)
	case ".gif":
		return gif.Decode(reader)
	case ".bmp":
		return bmp.Decode(reader)
	case ".webp":
		return webp.Decode(reader)
	case ".tiff":
		return tiff.Decode(reader)
	default:
		// Try generic decode
		img, _, err := image.Decode(reader)
		return img, err
	}
}

func (c *imageConverter) encode(img image.Image, format string, quality int) ([]byte, string, error) {
	var buf bytes.Buffer

	// Set default quality if not specified
	if quality == 0 {
		quality = 90
	}
	if quality < 1 {
		quality = 1
	}
	if quality > 100 {
		quality = 100
	}

	var err error
	var mimeType string

	switch format {
	case ".png":
		err = png.Encode(&buf, img)
		mimeType = "image/png"

	case ".jpg", ".jpeg":
		err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality})
		mimeType = "image/jpeg"

	case ".gif":
		err = gif.Encode(&buf, img, nil)
		mimeType = "image/gif"

	case ".bmp":
		err = bmp.Encode(&buf, img)
		mimeType = "image/bmp"

	case ".tiff":
		err = tiff.Encode(&buf, img, &tiff.Options{Compression: tiff.Deflate})
		mimeType = "image/tiff"

	case ".webp":
		// WebP encoding requires external library; fall back to JPEG
		err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality})
		mimeType = "image/jpeg"

	default:
		return nil, "", fmt.Errorf("unsupported output format: %s", format)
	}

	if err != nil {
		return nil, "", err
	}

	return buf.Bytes(), mimeType, nil
}
