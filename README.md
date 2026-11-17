# Weatherman07

Security research blog + portfolio. Black and yellow, Bleach-flavoured, terminal-brutalist.
A small static-site generator: write posts in Markdown, build to plain HTML, host anywhere.
No JS framework, no analytics, no third-party requests.

## Run it

WSL / Linux / macOS:

```bash
./dev.sh --serve        # http://localhost:8000, rebuilds on save, shows drafts
./dev.sh                # production build into dist/
```

Windows (PowerShell):

```powershell
python -m venv .venv; .\.venv\Scripts\pip install -r requirements-media.txt
.\.venv\Scripts\python build.py --serve
```

## Make it yours

1. [`site.toml`](site.toml): hero name halves, tagline, chips, links, final `url`.
2. [`content/about.md`](content/about.md).
3. Delete the sample post and write your own.
4. Fonts: drop these OFL-licensed files into `static/fonts/` (the site falls back to system fonts until you do):
   `Anton-Regular.woff2`, `PermanentMarker-Regular.woff2`, `JetBrainsMono-Regular.woff2`, `JetBrainsMono-Bold.woff2`, `NotoSerifJP-Black.woff2`.
5. Art: the hero slash and halftone are CSS/SVG placeholders in `templates/index.html` and `static/style.css`.

## Background video (themed)

Instead of ASCII, the site can use a full video as its background, graded to the theme: glowing yellow line-art on black.
Flat fills (white, black, red, blue) fall to black, so it works on any footage and never produces a bright wall.

```bash
python tools/themevideo.py path/to/video.mp4          # writes static/video/bg.mp4 and bg.jpg (add --webm for a VP9 copy)
python tools/themevideo.py video.mp4 --sigma 3 --gain 4   # thinner / brighter lines
python tools/themevideo.py video.mp4 --max-seconds 170    # only the first 2:50 (it loops); --start N skips ahead
```

- Needs OpenCV (`requirements-media.txt`) and ffmpeg (on PATH, or inside WSL on Windows). The source file is only read.
- When `static/video/bg.mp4` exists, the site uses the video and skips the ASCII canvas. Delete it to go back to ASCII.
- Blog post pages have no animated background at all (nothing to download, nothing behind the text). It is controlled by `no_bg=True`
  on the post pages in `build.py`.
- To shorten an existing `bg.mp4` without re-encoding: `ffmpeg -i bg.mp4 -c copy -t 170 -movflags +faststart out.mp4`.
- The video carries on across pages: each page saves the playback position in `sessionStorage` and the next page resumes from there
  (plus the time spent in between, so it is as if it never stopped). This needs the host to support HTTP range requests, which Cloudflare,
  Netlify and GitHub Pages all do; the dev server in `build.py` does too.
- The video starts after the page loads, shows a poster frame only for reduced-motion and data-saver visitors, and pauses in background tabs.
  Tune its opacity with `.bg-video.on` in `static/style.css`.
- Size scales with length. Raise `--crf-webm` / `--crf-mp4` (or lower `--width`) for smaller files.

## ASCII art background

Used when there is no background video. A random picture is drawn as yellow ASCII text on a canvas behind every page except blog posts
(strongest on the home page); GIFs animate. `/?bg=<id>` pins a specific one.

- Put images, GIFs or videos (`png`, `jpg`, `webp`, `gif`, `mp4`, `webm`, `mov`, `mkv`) in `art-src/`, then run the build. Each becomes a small JSON file in `static/ascii/`.
- Videos use only their first 6 seconds (about 10 frames per second, max 60 frames) and then loop. Trim a clip to the part you want first;
  change `ASCII_VIDEO_SECONDS` / `ASCII_MAX_VIDEO_FRAMES` in `build.py` to allow longer ones (bigger files).
- Video decoding needs OpenCV, which `requirements-media.txt` installs. On Windows, keep the project in a short path (e.g. `C:\dev\weatherman07`),
  otherwise pip can fail with "No such file or directory" on long folder names.
- Only the ASCII text is published. The originals in `art-src/` stay local (the folder is git-ignored).
- Delete a file from `art-src/` and its ASCII is removed on the next build.
- Tuning lives in `build.py` (`ASCII_RAMP`, `ASCII_COLS_*`, the gamma in `to_text`) and `#ascii-bg` opacity in `static/style.css`.
- The current set is *Bleach: Thousand-Year Blood War* stills and GIFs. They are copyrighted by their owners; the site only ships
  ASCII renderings of them, but credit the source and remove any a rights holder asks you to.

## Writing a blog

Create `content/posts/YYYY-MM-DD-my-slug.md` (URL is `/blogs/my-slug/`):

```markdown
+++
title = "Pre-auth RCE in Acme Router"
date = 2026-11-16
summary = "One sentence for lists and link previews."
tags = ["rce", "iot"]
cves = ["CVE-2026-12345"]          # optional badges
severity = "critical"              # optional: critical | high | medium | low | info
disclosure = "Reported 2026-05-01, fixed 2026-08-12 (v2.4.1)"   # optional
draft = false                      # true hides it from the built site
+++

Body in Markdown...
```

Supported: highlighted code with copy buttons, tables, footnotes, `!!! warning "Title"` callouts, table of contents (3+ headings),
reading time, tags, full-text search with tag filters on `/blogs/`, sitemap. There is no RSS feed. Images go in `static/` (served at `/assets/`):
`![alt](/assets/shot.png)`.

## Site behaviour

- One theme: black and yellow. There is no light/dark switch.
- Intro title card plays once per session on the home page (any key or click skips it; off with reduced-motion).
- `j` / `k` scroll, `g` / `G` top and bottom, `/` focuses the blog search.

## Deploy

**Live setup: GitHub Pages.** The repo is named `<account>.github.io` and `.github/workflows/deploy.yml` builds and publishes `dist/` on every
push to `main` (Settings → Pages → Source: *GitHub Actions*). `url` in `site.toml` is the `https://<account>.github.io` address and
`base_path` stays empty. GitHub's free plan needs the repo to be public for Pages.

### Alternative: private repo + free host

The site is plain static files, so any host works. The setup used here keeps the GitHub repo **private** and lets a free host
(Cloudflare Pages or Netlify) build it and serve it under a name you choose, e.g. `weatherman07.pages.dev`.

1. Put the project in a normal folder, commit, and push it to a **private** repo.
2. On the host, connect that repo (authorise only that one repository) and use:
   - Build command: `pip install -r requirements.txt && python build.py`
   - Output directory: `dist`
   - Python: `.python-version` already says 3.12 (or set an env var `PYTHON_VERSION=3.12`)
   - Site/project name: the name you want in the address
3. Set `url` in `site.toml` to the final address (no trailing slash) and keep `base_path = ""`, then push again.

No repo at all? Run `python build.py` and upload the `dist/` folder by hand (Netlify Drop, or Cloudflare Pages "Direct upload").

The host only needs `requirements.txt` (markdown, pygments, jinja2). The generated ASCII files and background video are committed, and your
original images/videos in `art-src/` stay local (git-ignored). `requirements-media.txt` is for working locally on those.

## Staying anonymous

- Commit with a noreply identity: `git config user.name "Weatherman07"` and `git config user.email "<id>+<username>@users.noreply.github.com"` before the first commit
  (GitHub Settings → Emails shows the address; tick "Keep my email addresses private" and "Block command line pushes that expose my email").
- Strip metadata from any images you add (EXIF location, device), and avoid usernames or paths in screenshots.
- Redact tokens, cookies, internal hostnames and customer data in write-ups, and confirm the vendor's disclosure timeline before publishing.
