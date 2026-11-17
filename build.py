#!/usr/bin/env python3
"""Small static site generator for a security research blog + portfolio.

    python build.py                 build into ./dist
    python build.py --serve         build, serve on http://localhost:8000 and rebuild on change
                                    (drafts are visible in --serve mode)
"""
from __future__ import annotations

import argparse
import datetime as dt
import functools
import html as html_lib
import http.server
import json
import os
import re
import shutil
import socketserver
import threading
import time
import tomllib
from email.utils import format_datetime
from pathlib import Path

import markdown
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pygments.formatters import HtmlFormatter
from pygments.style import Style
from pygments.token import Comment, Error, Generic, Keyword, Name, Number, Operator, Punctuation, String, Token


class VoidStyle(Style):
    """Yellow-on-black code theme; code blocks stay black in both site themes."""
    background_color = "#000000"
    styles = {
        Token: "#efe9d6",
        Comment: "italic #7a7458",
        Keyword: "bold #ffd60a",
        Keyword.Type: "#ffd60a",
        Operator: "#ffd60a",
        Punctuation: "#b5ae92",
        Name.Function: "#fff3b0",
        Name.Class: "bold #fff3b0",
        Name.Decorator: "#ffd60a",
        Name.Builtin: "#e8c98a",
        Name.Tag: "#ffd60a",
        String: "#e8c98a",
        Number: "#ff9d2e",
        Generic.Deleted: "#ff5c5c",
        Generic.Inserted: "#7bd88f",
        Generic.Heading: "bold",
        Error: "",
    }


ROOT = Path(__file__).resolve().parent
CONTENT = ROOT / "content"
TEMPLATES = ROOT / "templates"
STATIC = ROOT / "static"
DIST = ROOT / "dist"
ART_SRC = ROOT / "art-src"          # your source images/gifs (kept out of git and never published)
ASCII_DIR = STATIC / "ascii"        # baked ASCII JSON (this is what gets published)
WORDS_PER_MINUTE = 220
ASCII_RAMP = " .'`:;-~+=*oxO#%8@"   # dark -> light
ASCII_COLS_STILL, ASCII_COLS_GIF, ASCII_MAX_FRAMES = 300, 140, 18
ASCII_VIDEO_EXTS = {".mp4", ".webm", ".mov", ".mkv", ".m4v"}
ASCII_VIDEO_SECONDS = 6             # only the first N seconds of a video are used (it loops)
ASCII_MAX_VIDEO_FRAMES = 60


# --------------------------------------------------------------------------- helpers
def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def split_front_matter(text: str) -> tuple[dict, str]:
    """TOML front matter delimited by +++ lines."""
    m = re.match(r"\A\+\+\+\s*\n(.*?)\n\+\+\+\s*\n?(.*)\Z", text, re.DOTALL)
    if not m:
        return {}, text
    return tomllib.loads(m.group(1)), m.group(2)


def flatten_toc(tokens: list[dict], out: list[dict] | None = None) -> list[dict]:
    out = [] if out is None else out
    for t in tokens:
        out.append({"id": t["id"], "name": t["name"], "level": t["level"]})
        flatten_toc(t.get("children", []), out)
    return out


def render_markdown(text: str, base_path: str) -> tuple[str, list[dict]]:
    md = markdown.Markdown(
        extensions=[
            "fenced_code", "codehilite", "tables", "toc", "footnotes",
            "attr_list", "sane_lists", "admonition",
        ],
        extension_configs={
            "codehilite": {"css_class": "codehilite", "guess_lang": False},
            "toc": {"permalink": "#", "permalink_title": "Link to this section", "toc_depth": "2-3"},
        },
    )
    html = md.convert(text)
    if base_path:  # make root-relative links/images work under a sub-path deployment
        html = re.sub(r'(href|src)="/(?!/)', rf'\1="{base_path}/', html)
    return html, flatten_toc(md.toc_tokens)


def to_date(value) -> dt.date:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    return dt.date.fromisoformat(str(value))


# --------------------------------------------------------------------------- content
def load_config(local: bool, port: int) -> dict:
    cfg = tomllib.loads((ROOT / "site.toml").read_text("utf-8"))
    cfg["base_path"] = cfg.get("base_path", "").rstrip("/")
    cfg["url"] = cfg["url"].rstrip("/")
    cfg["links"] = [l for l in cfg.get("links", []) if l.get("url")]
    # A graded background video (made with tools/themevideo.py) replaces the ASCII canvas when present.
    cfg["has_bg_video"] = (STATIC / "video" / "bg.mp4").exists()
    if local:
        cfg["base_path"] = ""
        cfg["url"] = f"http://localhost:{port}"
    return cfg


def load_posts(cfg: dict, include_drafts: bool) -> list[dict]:
    posts = []
    for path in sorted((CONTENT / "posts").glob("*.md")):
        meta, body = split_front_matter(path.read_text("utf-8"))
        draft = bool(meta.get("draft", False))
        if draft and not include_drafts:
            continue
        for required in ("title", "date"):
            if required not in meta:
                raise SystemExit(f"{path.name}: missing '{required}' in front matter")
        html, toc = render_markdown(body, cfg["base_path"])
        words = len(re.findall(r"\w+", re.sub(r"<[^>]+>", " ", html)))
        tags = [str(t) for t in meta.get("tags", [])]
        posts.append({
            "slug": meta.get("slug") or re.sub(r"^\d{4}-\d{2}-\d{2}-", "", path.stem),
            "title": meta["title"],
            "date": to_date(meta["date"]),
            "updated": to_date(meta["updated"]) if "updated" in meta else None,
            "summary": meta.get("summary", ""),
            "tags": [{"name": t, "slug": slugify(t)} for t in tags],
            "cves": list(meta.get("cves", [])),
            "severity": str(meta.get("severity", "")).lower(),
            "disclosure": meta.get("disclosure", ""),
            "draft": draft,
            "html": html,
            "toc": toc if len(toc) >= 3 else [],
            "reading_time": max(1, round(words / WORDS_PER_MINUTE)),
        })
    posts.sort(key=lambda p: p["date"], reverse=True)
    for i, p in enumerate(posts):
        p["no"] = f"{len(posts) - i:02d}"  # chronological blog number, oldest = 01
        p["newer"] = posts[i - 1] if i > 0 else None
        p["older"] = posts[i + 1] if i + 1 < len(posts) else None
    return posts


def collect_tags(posts: list[dict]) -> list[dict]:
    tags: dict[str, dict] = {}
    for p in posts:
        for t in p["tags"]:
            entry = tags.setdefault(t["slug"], {"name": t["name"], "slug": t["slug"], "posts": []})
            entry["posts"].append(p)
    return sorted(tags.values(), key=lambda t: (-len(t["posts"]), t["name"].lower()))


# --------------------------------------------------------------------------- ASCII art
def bake_ascii() -> None:
    """Turn images/gifs in art-src/ into ASCII JSON in static/ascii/ (+ an index.json manifest).

    Only the ASCII text is published, never the original pictures. Outputs newer than their
    source are skipped, so normal builds stay fast.
    """
    if not ART_SRC.exists():
        return
    try:
        from PIL import Image, ImageOps
    except ImportError:
        print("Pillow is not installed: skipping ASCII art (pip install -r requirements.txt)")
        return

    def to_text(img, cols: int) -> tuple[str, int]:
        w, h = img.size
        rows = max(1, round(cols * h / w * 0.6))          # a monospace cell is ~0.6 as wide as tall
        gray = ImageOps.equalize(ImageOps.autocontrast(img.convert("L").resize((cols, rows), Image.Resampling.LANCZOS), cutoff=2), mask=None)
        px, n = gray.load(), len(ASCII_RAMP)
        # gamma < 1 lifts the shadows: most TYBW stills are dark, and a straight mapping bakes to empty space
        lines = ["".join(ASCII_RAMP[min(n - 1, int((px[x, y] / 255) ** 0.8 * n))] for x in range(cols)).rstrip()
                 for y in range(rows)]
        return "\n".join(lines), rows

    def bake_video(src: Path, out: Path) -> None:
        """Sample the first ASCII_VIDEO_SECONDS of a video at ~10 fps (capped) into ASCII frames."""
        try:
            import cv2
        except ImportError:
            print(f"  skipping {src.name}: video needs OpenCV (pip install -r requirements.txt)")
            return
        cap = cv2.VideoCapture(str(src))
        if not cap.isOpened():
            print(f"  skipping {src.name}: could not open video")
            return
        src_fps = cap.get(cv2.CAP_PROP_FPS) or 24.0
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or int(src_fps * ASCII_VIDEO_SECONDS)
        span = max(1, min(total, int(src_fps * ASCII_VIDEO_SECONDS)))
        n = max(2, min(ASCII_MAX_VIDEO_FRAMES, round(span / src_fps * 10)))
        frames, rows, aspect = [], 1, 16 / 9
        for k in range(n):
            cap.set(cv2.CAP_PROP_POS_FRAMES, int(k * span / n))
            ok, bgr = cap.read()
            if not ok:
                break
            img = Image.fromarray(cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB))
            aspect = img.size[0] / img.size[1]
            text, rows = to_text(img, ASCII_COLS_GIF)
            frames.append(text)
        cap.release()
        if not frames:
            print(f"  skipping {src.name}: no frames could be read")
            return
        fps = max(4, min(14, round(len(frames) / (span / src_fps))))
        out.write_text(json.dumps({"id": src.stem, "cols": ASCII_COLS_GIF, "rows": rows, "aspect": round(aspect, 4),
                                   "fps": fps, "frames": frames}, ensure_ascii=False, separators=(",", ":")), "utf-8")
        print(f"  ascii: {src.name} -> {out.name} ({len(frames)} frames, first {span / src_fps:.1f}s)")

    ASCII_DIR.mkdir(parents=True, exist_ok=True)
    manifest, keep = [], {"index.json"}
    exts = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
    for src in sorted(p for p in ART_SRC.iterdir() if p.suffix.lower() in exts | ASCII_VIDEO_EXTS):
        out = ASCII_DIR / f"{src.stem}.json"
        keep.add(out.name)
        if src.suffix.lower() in ASCII_VIDEO_EXTS:
            manifest.append({"id": src.stem, "file": out.name, "animated": True})
            if not (out.exists() and out.stat().st_mtime >= src.stat().st_mtime):
                bake_video(src, out)
            continue
        with Image.open(src) as im:
            n = getattr(im, "n_frames", 1)
            manifest.append({"id": src.stem, "file": out.name, "animated": n > 1})
            if out.exists() and out.stat().st_mtime >= src.stat().st_mtime:
                continue
            animated = n > 1
            cols = ASCII_COLS_GIF if animated else ASCII_COLS_STILL
            picks = sorted({round(i * (n - 1) / max(min(n, ASCII_MAX_FRAMES) - 1, 1)) for i in range(min(n, ASCII_MAX_FRAMES))}) if animated else [0]
            total_ms = 0
            for i in range(n):                              # real playback length of the original gif
                im.seek(i)
                total_ms += max(20, im.info.get("duration", 80))
            frames, rows = [], 1
            for i in picks:
                im.seek(i)
                text, rows = to_text(im.convert("RGB"), cols)
                frames.append(text)
            fps = max(4, min(14, round(len(frames) / (total_ms / 1000)))) if animated else 0
            out.write_text(json.dumps({"id": src.stem, "cols": cols, "rows": rows, "aspect": round(im.size[0] / im.size[1], 4),
                                       "fps": fps, "frames": frames}, ensure_ascii=False, separators=(",", ":")), "utf-8")
            print(f"  ascii: {src.name} -> {out.name} ({len(frames)} frame{'s' if len(frames) != 1 else ''})")
    for stale in ASCII_DIR.glob("*.json"):                  # drop output for sources you deleted
        if stale.name not in keep:
            stale.unlink()
    new = json.dumps(manifest, separators=(",", ":"))
    idx = ASCII_DIR / "index.json"
    if not idx.exists() or idx.read_text("utf-8") != new:
        idx.write_text(new, "utf-8")


# --------------------------------------------------------------------------- build
def build(local: bool = False, port: int = 8000) -> None:
    cfg = load_config(local, port)
    bake_ascii()
    posts = load_posts(cfg, include_drafts=local)
    tags = collect_tags(posts)
    about_meta, about_body = split_front_matter((CONTENT / "about.md").read_text("utf-8"))
    about_html, _ = render_markdown(about_body, cfg["base_path"])

    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True, lstrip_blocks=True,
    )
    env.filters["date"] = lambda d, fmt="%d %b %Y": d.strftime(fmt)
    env.filters["rfc822"] = lambda d: format_datetime(dt.datetime(d.year, d.month, d.day, tzinfo=dt.timezone.utc))
    env.globals.update(
        site=cfg,
        u=lambda path: f"{cfg['base_path']}{path}",
        now=dt.datetime.now(dt.timezone.utc),
        all_tags=tags,
    )

    if DIST.exists():
        # On Windows a file the browser is streaming (the background video) can't be deleted: leave it in place.
        shutil.rmtree(DIST, onerror=lambda func, path, exc: None)
    DIST.mkdir(exist_ok=True)

    def write(rel: str, template: str, **ctx) -> None:
        url_path = "/" + rel.removesuffix("index.html")
        out = DIST / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            env.get_template(template).render(path=url_path, canonical=cfg["url"] + url_path, **ctx),
            "utf-8",
        )

    write("index.html", "index.html", section="home", posts=posts[:5], total_posts=len(posts))
    write("blogs/index.html", "blog.html", section="blogs", page_title="Blogs", posts=posts)
    for p in posts:
        write(f"blogs/{p['slug']}/index.html", "post.html", section="blogs", post=p, no_bg=True,
              page_title=p["title"], description=p["summary"], og_type="article")
    write("tags/index.html", "tags.html", section="tags", page_title="Tags", tags=tags)
    for t in tags:
        write(f"tags/{t['slug']}/index.html", "tag.html", section="tags", tag=t, page_title=f"#{t['name']}")
    write("about/index.html", "about.html", section="about", page_title="About", content=about_html, about=about_meta)
    write("404.html", "404.html", section="404", page_title="Not found")
    write("sitemap.xml", "sitemap.xml", posts=posts, tags=tags)
    # Full-text index for the client-side search on /blogs/ (slug -> plain text of the post).
    index = {
        p["slug"]: re.sub(r"\s+", " ", html_lib.unescape(re.sub(r"<[^>]+>", " ", p["html"]))).strip()[:12000]
        for p in posts
    }
    (DIST / "search.json").write_text(json.dumps(index, ensure_ascii=False), "utf-8")
    (DIST / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {cfg['url']}{cfg['base_path']}/sitemap.xml\n")

    def copy_changed(src, dst):                    # skip files that are already up to date (or locked while playing)
        d = Path(dst)
        if d.exists() and d.stat().st_size == Path(src).stat().st_size and d.stat().st_mtime >= Path(src).stat().st_mtime:
            return dst
        return shutil.copy2(src, dst)

    shutil.copytree(STATIC, DIST / "assets", dirs_exist_ok=True, copy_function=copy_changed)
    # Syntax-highlighting themes for both color schemes.
    css = HtmlFormatter(style=VoidStyle).get_style_defs(".codehilite")
    (DIST / "assets" / "pygments.css").write_text(css, "utf-8")

    n_draft = sum(p["draft"] for p in posts)
    print(f"built {len(posts)} posts ({n_draft} drafts), {len(tags)} tags -> {DIST}")


# --------------------------------------------------------------------------- dev server
def snapshot() -> float:
    watched = [ROOT / "site.toml", *CONTENT.rglob("*"), *TEMPLATES.rglob("*"), *STATIC.rglob("*"),
               *(ART_SRC.rglob("*") if ART_SRC.exists() else [])]
    return max((p.stat().st_mtime for p in watched if p.exists()), default=0)


class RangeHandler(http.server.SimpleHTTPRequestHandler):
    """Static file handler with HTTP Range support, so <video> can seek (real hosts all do this)."""

    def end_headers(self) -> None:
        self.send_header("Accept-Ranges", "bytes")
        super().end_headers()

    def send_head(self):
        rng = self.headers.get("Range")
        path = self.translate_path(self.path)
        m = re.match(r"bytes=(\d*)-(\d*)$", (rng or "").strip())
        if not m or not os.path.isfile(path):
            return super().send_head()
        size = os.path.getsize(path)
        first, last = m.groups()
        if first:
            start, end = int(first), min(int(last) if last else size - 1, size - 1)
        elif last:                                   # suffix range: the last N bytes
            start, end = max(0, size - int(last)), size - 1
        else:
            return super().send_head()
        if start > end or start >= size:
            self.send_error(416, "Requested Range Not Satisfiable")
            return None
        f = open(path, "rb")
        f.seek(start)
        self._range_left = end - start + 1
        self.send_response(206)
        self.send_header("Content-Type", self.guess_type(path))
        self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.send_header("Content-Length", str(self._range_left))
        self.end_headers()
        return f

    def copyfile(self, source, outputfile) -> None:
        left = getattr(self, "_range_left", None)
        self._range_left = None
        try:
            if left is None:
                return super().copyfile(source, outputfile)
            while left > 0:
                chunk = source.read(min(64 * 1024, left))
                if not chunk:
                    break
                outputfile.write(chunk)
                left -= len(chunk)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass                                     # the browser cancelled (e.g. a seek); not an error


def serve(port: int) -> None:
    build(local=True, port=port)

    def watch() -> None:
        last = snapshot()
        while True:
            time.sleep(1)
            current = snapshot()
            if current != last:
                last = current
                try:
                    build(local=True, port=port)
                except Exception as exc:  # keep serving while you fix a typo
                    print(f"build failed: {exc}")

    threading.Thread(target=watch, daemon=True).start()
    handler = functools.partial(RangeHandler, directory=str(DIST))
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", port), handler) as httpd:
        print(f"serving http://localhost:{port}  (Ctrl+C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--serve", action="store_true", help="serve locally and rebuild on change")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    serve(args.port) if args.serve else build()
