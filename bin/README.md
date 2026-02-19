# Bundled Tools

Pre-packaged Windows binaries that ship with the repository.
The converter discovers these automatically — no PATH configuration needed.

## Directory Layout

```
bin/
├── ffmpeg/              FFmpeg (audio/video conversion)
│   ├── ffmpeg.exe
│   └── *.dll            Shared libraries (avcodec, avformat, …)
├── imagemagick/         ImageMagick (image conversion)
│   ├── magick.exe
│   └── *.dll            CORE_RL + VC++ runtime libraries
├── pandoc/              Pandoc (document conversion)
│   └── pandoc.exe
└── README.md            This file
```

## Versions

| Tool | Version | Download |
|------|---------|----------|
| FFmpeg | Latest GPL shared | https://github.com/BtbN/FFmpeg-Builds/releases |
| ImageMagick | 7.1.2 Q16-HDRI portable | https://imagemagick.org/archive/binaries/ |
| Pandoc | 3.9 | https://github.com/jgm/pandoc/releases |

## How It Works

The converter checks `bin/<tool>/` first, then falls back to a flat `bin/`
layout, and finally the system PATH.

## What Works Without These Binaries

Even without external tools the converter still handles:
- Basic images: PNG, JPEG, GIF, BMP, TIFF, WebP (pure Go)
- Bank file formatting (CSV / Excel)
- TNEF / winmail.dat extraction
