#!/usr/bin/env python3
"""Grade a video to the Weatherman07 look and export it as a web background.

The grade is polarity-independent line extraction: thin lines, edges and type become glowing
yellow, flat fills (white, black, red, blue ...) fall to black. It works on white-paper sketches,
colour-block title cards and dark scenes alike, and never produces a bright yellow wall.

    python tools/themevideo.py INPUT.mp4
    python tools/themevideo.py INPUT.mp4 --out static/video --width 960 --poster-at 29

Writes bg.webm (VP9), bg.mp4 (H.264) and bg.jpg (poster) into --out. Needs OpenCV (pip) and ffmpeg
(on PATH, or inside WSL on Windows). The source video is only read, never copied or modified.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

import cv2
import numpy as np

YELLOW_BGR = np.array([10, 214, 255], np.float32) / 255.0        # #ffd60a


def find_ffmpeg() -> tuple[list[str], bool]:
    """Return (command prefix, runs_in_wsl)."""
    exe = shutil.which("ffmpeg")
    if exe:
        return [exe], False
    if shutil.which("wsl"):
        probe = subprocess.run(["wsl", "-e", "which", "ffmpeg"], capture_output=True, text=True)
        if probe.returncode == 0:
            return ["wsl", "-e", "ffmpeg"], True
    sys.exit("ffmpeg not found (install it, or install it inside WSL)")


def for_ffmpeg(path: Path, wsl: bool) -> str:
    s = str(path.resolve())
    if wsl and len(s) > 1 and s[1] == ":":
        return "/mnt/" + s[0].lower() + s[2:].replace("\\", "/")
    return s


def grade(frame: np.ndarray, sigma: float, gain: float, floor: float) -> np.ndarray:
    """BGR frame -> uint8 'ink' map (0 = flat area, 255 = strong line).

    `floor` removes faint texture (paper grain, compression noise, soft shading) so it costs no bytes.
    """
    g = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(np.float32) / 255.0
    ink = np.abs(g - cv2.GaussianBlur(g, (0, 0), sigma))
    ink = np.clip((ink - floor) / (1.0 - floor), 0, 1)
    return (np.clip(ink * gain, 0, 1) ** 0.85 * 255).astype(np.uint8)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=Path)
    ap.add_argument("--out", type=Path, default=Path("static/video"))
    ap.add_argument("--name", default="bg")
    ap.add_argument("--width", type=int, default=1280, help="output width; 800 = smaller/softer, 1280 = crisp lines")
    ap.add_argument("--fps", type=float, default=24, help="output frame rate (15 is fine for a dim background and saves ~35%)")
    ap.add_argument("--sigma", type=float, default=3.5, help="line thickness the effect keeps (px at --width)")
    ap.add_argument("--gain", type=float, default=3.4, help="line brightness")
    ap.add_argument("--floor", type=float, default=0.045, help="ignore detail fainter than this (0-1); bigger = smaller file")
    ap.add_argument("--webm", action="store_true", help="also write a VP9 .webm (much larger for this footage)")
    ap.add_argument("--crf-webm", type=int, default=42)
    ap.add_argument("--crf-mp4", type=int, default=42, help="higher = smaller file (42 ~ 13 MB for 4:23 at 1280px/24fps)")
    ap.add_argument("--poster-at", type=float, default=None, help="second to use for the poster (default: middle)")
    ap.add_argument("--start", type=float, default=0, help="start at this second (handy for quality tests)")
    ap.add_argument("--max-seconds", type=float, default=0, help="only process N seconds from the start (0 = to the end)")
    args = ap.parse_args()

    if not args.input.exists():
        sys.exit(f"not found: {args.input}")
    args.out.mkdir(parents=True, exist_ok=True)
    ff, wsl = find_ffmpeg()

    cap = cv2.VideoCapture(str(args.input))
    if not cap.isOpened():
        sys.exit("could not open the video")
    fps = cap.get(cv2.CAP_PROP_FPS) or 24.0
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    sw, sh = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)), int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    W = args.width - args.width % 2
    H = round(W * sh / sw / 2) * 2
    first = int(args.start * fps)
    limit = int(args.max_seconds * fps) if args.max_seconds else total - first
    limit = min(limit, total - first) if total else limit
    if first:
        cap.set(cv2.CAP_PROP_POS_FRAMES, first)
    poster_at = (args.poster_at - args.start) if args.poster_at is not None else (limit / fps) / 2
    out_fps = min(args.fps, fps)
    print(f"{args.input.name}: {sw}x{sh} @ {fps:.3f}fps, {limit / fps:.1f}s -> {W}x{H} @ {out_fps:g}fps")

    webm, mp4, poster = (args.out / f"{args.name}.webm", args.out / f"{args.name}.mp4", args.out / f"{args.name}.jpg")
    mix = "format=gbrp,colorchannelmixer=rr=1:gg=0.839:bb=0.039,split[a][b]"   # grey ink -> #ffd60a
    # H.264 MP4 plays everywhere and is far smaller than VP9 for this kind of footage; WebM is opt-in.
    cmd = ff + [
        "-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "gray", "-s", f"{W}x{H}", "-r", f"{out_fps:.5f}", "-i", "-",
        "-filter_complex", f"[0:v]{mix}",
        "-map", "[b]", "-c:v", "libx264", "-crf", str(args.crf_mp4), "-preset", "slower", "-tune", "animation",
        "-pix_fmt", "yuv420p", "-movflags", "+faststart", "-an", for_ffmpeg(mp4, wsl),
    ]
    if args.webm:
        cmd += ["-map", "[a]", "-c:v", "libvpx-vp9", "-crf", str(args.crf_webm), "-b:v", "0", "-row-mt", "1",
                "-deadline", "good", "-cpu-used", "3", "-pix_fmt", "yuv420p", "-an", for_ffmpeg(webm, wsl)]
    else:
        cmd[cmd.index("-filter_complex") + 1] = f"[0:v]{mix.replace(',split[a][b]', '')}[b]"
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)

    start, done, sent, poster_frame, next_emit = time.time(), 0, 0, int(poster_at * fps), 0.0
    try:
        while done < limit:
            ok, frame = cap.read()
            if not ok:
                break
            done += 1
            if (done - 1) < next_emit and (done - 1) != poster_frame:   # frame-rate reduction: skip frames
                continue
            ink = grade(cv2.resize(frame, (W, H), interpolation=cv2.INTER_AREA), args.sigma, args.gain, args.floor)
            if done - 1 == poster_frame:
                cv2.imwrite(str(poster), (ink[..., None] * YELLOW_BGR).astype(np.uint8), [cv2.IMWRITE_JPEG_QUALITY, 78])
            if (done - 1) >= next_emit:
                proc.stdin.write(ink.tobytes())
                sent += 1
                next_emit += fps / out_fps
            if done % 600 == 0:
                rate = done / (time.time() - start)
                print(f"  {done}/{limit} frames ({100 * done // limit}%), {rate:.0f} fps in, ~{(limit - done) / rate:.0f}s left", flush=True)
    finally:
        cap.release()
        proc.stdin.close()
        code = proc.wait()
    if code != 0:
        sys.exit(f"ffmpeg failed (exit {code})")
    for p in (webm, mp4, poster):
        if p.exists() and (p != webm or args.webm):
            print(f"  {p.name}: {p.stat().st_size / 1e6:.1f} MB")
    print("done")


if __name__ == "__main__":
    main()
