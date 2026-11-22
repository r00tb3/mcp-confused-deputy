"""Record the four-step walkthrough as a ~90s video for the README.

The UI is gated: the primary button unlocks each step, step 3 is a three-question
quiz, and step 4 only unlocks after it. The recorder follows that real path, so
the video shows the flow a visitor actually gets.

Run:  python3 demo/record-walkthrough.py
Out:  demo/_video/<hash>.webm
"""
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).parent
W, H = 1024, 640

# correct option index for each of the three quiz questions
ANSWERS = [1, 1, 1]

# the fix: gate moved above the file I/O
FIXED_CODE = '''escalate = arguments.get("escalate") is True

# the elevation gate — before anything executes
if self.mode == "clean" and escalate and not grant:
    return rpc_error(request_id, -32002, "Elevation required")

# path resolution and file I/O
if name == "fs.read":
    text, error = self.read_file(arguments["path"])
else:
    text, error = self.write_file(arguments["path"], arguments["content"])

# the side effect
if escalate:
    ok, detail = self.reload_service(request_key, caller)'''


def beat(pg, seconds):
    """Pause, but keep painting so the recording is not a freeze-frame."""
    end = time.time() + seconds
    while time.time() < end:
        pg.mouse.move(W // 2, H // 2 + 1)
        time.sleep(0.2)


def wait_enabled(pg, sel, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if pg.query_selector(sel) and pg.is_enabled(sel) and pg.is_visible(sel):
            return True
        time.sleep(0.25)
    return False


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--force-color-profile=srgb"])
        ctx = browser.new_context(
            viewport={"width": W, "height": H},
            record_video_dir=str(OUT / "_video"),
            record_video_size={"width": W, "height": H},
            device_scale_factor=1,
        )
        pg = ctx.new_page()
        pg.goto("http://127.0.0.1:8080/", wait_until="networkidle")
        pg.evaluate("localStorage.setItem('sec4412-theme','dark')")
        pg.reload(wait_until="networkidle")

        # ── intro: the ticket you inherit ──
        beat(pg, 4)
        pg.click("#openBtn")
        beat(pg, 3)

        # ── step 1: read the ticket ──
        beat(pg, 4)
        pg.mouse.wheel(0, 300)
        beat(pg, 3)
        pg.mouse.wheel(0, -300)
        beat(pg, 2)
        pg.click("#primaryBtn")          # -> step 2
        beat(pg, 2)

        # ── step 2: reproduce the reload ──
        wait_enabled(pg, "#runBtn")
        pg.click("#runBtn")
        beat(pg, 9)                      # agent runs against the live broker
        wait_enabled(pg, "#primaryBtn")
        pg.click("#primaryBtn")          # -> step 3, read the audit
        beat(pg, 4)
        if pg.is_visible("#tabAudit"):
            pg.click("#tabAudit")
        beat(pg, 5)                      # the escalate field beside the declared ones

        # ── step 3: the quiz ──
        # Each answered question stays in the DOM and appends the next, so the
        # active question is always the last .q box. Options in older boxes stay
        # disabled, which is why the click is scoped rather than global.
        for i, ans in enumerate(ANSWERS):
            pg.wait_for_function(
                f'document.querySelectorAll("#qmount .q").length === {i + 1}',
                timeout=15000,
            )
            beat(pg, 2)                  # read the question
            pg.evaluate(
                """(ans) => {
                     const boxes = [...document.querySelectorAll('#qmount .q')];
                     const opts = [...boxes[boxes.length - 1].querySelectorAll('.opt')];
                     opts[ans].click();
                   }""",
                ans,
            )
            beat(pg, 2)                  # the explanation lands

        # ── step 4: write the fix ──
        wait_enabled(pg, "#primaryBtn")
        pg.click("#primaryBtn")
        beat(pg, 3)
        pg.wait_for_selector("#codeArea", timeout=15000)
        beat(pg, 4)
        # clear and paste the corrected ordering
        pg.click("#codeArea")
        pg.keyboard.press("Control+a")
        pg.keyboard.type(FIXED_CODE, delay=6)
        beat(pg, 3)
        pg.click("#verifyBtn")
        beat(pg, 7)                      # four checks turning green
        pg.mouse.wheel(0, 420)
        beat(pg, 6)                      # vuln/clean comparison
        pg.mouse.wheel(0, -420)
        beat(pg, 4)

        video = pg.video.path()
        ctx.close()
        browser.close()

    # Playwright writes a near-lossless webm; VP9 at CRF 34 is ~4.5x smaller and
    # still sharp on text. Falls back to the raw file if ffmpeg is missing.
    raw = Path(video)
    final = OUT / "walkthrough.webm"
    try:
        import subprocess

        import imageio_ffmpeg

        subprocess.run(
            [imageio_ffmpeg.get_ffmpeg_exe(), "-hide_banner", "-loglevel", "error",
             "-i", str(raw), "-c:v", "libvpx-vp9", "-crf", "34", "-b:v", "0",
             "-row-mt", "1", "-cpu-used", "2", "-an", str(final), "-y"],
            check=True,
        )
        print("encoded:", final, f"{final.stat().st_size / 1048576:.1f} MB")
    except Exception as exc:  # noqa: BLE001 - any failure should still leave a video
        print(f"encode skipped ({exc}); raw file at {raw}")
    finally:
        for leftover in (OUT / "_video").glob("*.webm"):
            leftover.unlink(missing_ok=True)
        try:
            (OUT / "_video").rmdir()
        except OSError:
            pass


if __name__ == "__main__":
    main()
