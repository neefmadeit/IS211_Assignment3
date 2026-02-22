import argparse
import csv
import io
import sys
import re
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from datetime import datetime
from collections import Counter, defaultdict

IMAGE_PATTERN = re.compile(r"""\.(?:jpg|gif|png)$""", re.IGNORECASE)

# Browser detection
RE_FIREFOX = re.compile(r"Firefox/\d", re.IGNORECASE)
RE_CHROME  = re.compile(r"(?:Chrome/\d|CriOS/\d)", re.IGNORECASE)  # Chrome (desktop) or iOS (CriOS)
RE_IE      = re.compile(r"(?:MSIE\s\d|Trident/.*rv:\d)", re.IGNORECASE)  # IE10 and IE11
RE_SAFARI  = re.compile(r"Safari/\d", re.IGNORECASE)
RE_NOT_SAFARI = re.compile(r"(Chrome/|CriOS/|Chromium/|Edg/|Edge/|OPR/|SamsungBrowser/)", re.IGNORECASE)

"""
Downloads the content at the URL and returns it as text.
"""
def download_text_from_url(url: str) -> str:

    try:
        req = Request(url, headers={"User-Agent": "assignment3/1.0"})
        with urlopen(req, timeout=60) as resp:
            raw = resp.read()
    except HTTPError as e:
        raise RuntimeError(f"HTTP error {e.code} while downloading {url}") from e
    except URLError as e:
        raise RuntimeError(f"Failed to reach {url}: {e.reason}") from e
    except Exception as e:
        raise RuntimeError(f"Unexpected error while downloading {url}: {e}") from e

    # Attempt decoding
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    # Last resort: replace undecodable characters
    return raw.decode("utf-8", errors="replace")

"""
Classify user agent into one of:
Firefox, Chrome, Internet Explorer, Safari.
If unrecognized, returns 'Other'.
"""
def classify_browser(user_agent: str) -> str:

    ua = user_agent or ""

    if RE_FIREFOX.search(ua):
        return "Firefox"

    # Must check Chrome before Safari, since Chrome UAs contain 'Safari'
    if RE_CHROME.search(ua) and "OPR/" not in ua and "Edg" not in ua:
        return "Chrome"

    if RE_IE.search(ua):
        return "Internet Explorer"

    # Safari must exclude Chrome/Edge/Opera/SamsungBrowser/etc.
    if RE_SAFARI.search(ua) and not RE_NOT_SAFARI.search(ua):
        return "Safari"

    return "Other"

def is_image_path(path: str) -> bool:
    """Return True if the path ends with .jpg, .gif, or .png."""
    if not path:
        return False
    return bool(IMAGE_PATTERN.search(path))


def parse_datetime(dt_str: str) -> datetime | None:
    """
    Parse 'MM/DD/YYYY HH:MM:SS' into a datetime.
    """
    if not dt_str:
        return None
    try:
        return datetime.strptime(dt_str.strip(), "%m/%d/%Y %H:%M:%S")
    except ValueError:
        return None


def process_csv_text(csv_text: str):
    """
    Processes the CSV text and computes:
      - total requests
      - image request count
      - browser counts
      - hour counts (0..23)
    Returns a dict with computed stats.
    """
    total_requests = 0
    image_requests = 0

    browser_counts = Counter()
    hour_counts = Counter()

    # Ensure all hours are present (even zero hits), to print all 24 later
    for h in range(24):
        hour_counts[h] = 0

    text_stream = io.StringIO(csv_text, newline="")
    reader = csv.reader(text_stream)

    for idx, row in enumerate(reader, start=1):
        # Expect: [path, datetime, user_agent, status, size]
        if not row or len(row) < 3:
            # Skip rows too small to be useful
            continue

        # Try to safely unpack columns with defaults
        path         = row[0].strip() if len(row) >= 1 else ""
        dt_str       = row[1].strip() if len(row) >= 2 else ""
        user_agent   = row[2].strip() if len(row) >= 3 else ""
        # status, size are present but not used for this assignment’s outputs
        # Kept for completeness:
        # status       = row[3].strip() if len(row) >= 4 else ""
        # size         = row[4].strip() if len(row) >= 5 else ""

        total_requests += 1

        # Part III: image detection
        if is_image_path(path):
            image_requests += 1

        # Part IV: browser classification
        bname = classify_browser(user_agent)
        if bname in ("Firefox", "Chrome", "Internet Explorer", "Safari"):
            browser_counts[bname] += 1
        else:
            # We track "Other" but it doesn't participate in "most popular" decision
            browser_counts["Other"] += 1

        # Part VI: hour extraction
        dt_obj = parse_datetime(dt_str)
        if dt_obj is not None:
            hour_counts[dt_obj.hour] += 1

    return {
        "total_requests": total_requests,
        "image_requests": image_requests,
        "browser_counts": browser_counts,
        "hour_counts": hour_counts,
    }

def pick_most_popular_browser(browser_counts: Counter) -> tuple[str, int] | None:
    """
    Returns (browser_name, count) for the most popular among:
      Firefox, Chrome, Internet Explorer, Safari.
    """
    candidates = ["Chrome", "Firefox", "Safari", "Internet Explorer"]
    present = [(b, browser_counts.get(b, 0)) for b in candidates]
    # If all zero, return None
    if all(count == 0 for _, count in present):
        return None
    # Choose the one with max count; tie broken by the order in 'candidates'
    best = max(present, key=lambda x: (x[1], -candidates.index(x[0])))
    return best


def main():
    parser = argparse.ArgumentParser(
        description="Download and analyze a web log CSV (image % and most popular browser; list hours by hits)."
    )
    parser.add_argument(
        "--url",
        required=True,
        help="URL of the CSV web log file. Example: https://example.com/log.csv",
    )
    parser.add_argument(
        "--save",
        default=None,
        help="Optional path to save a local copy of the downloaded log.",
    )
    parser.add_argument(
        "--precision",
        type=int,
        default=1,
        help="Decimal places for image percentage (default: 1).",
    )
    args = parser.parse_args()

    # Part I: download
    try:
        csv_text = download_text_from_url(args.url)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    # Optional save
    if args.save:
        try:
            with open(args.save, "w", encoding="utf-8", newline="") as f:
                f.write(csv_text)
        except Exception as e:
            print(f"Warning: could not save to {args.save}: {e}", file=sys.stderr)

    # Part II/III/IV/VI: process and report
    stats = process_csv_text(csv_text)

    total = stats["total_requests"]
    images = stats["image_requests"]
    image_pct = (images / total * 100.0) if total else 0.0

    print(f"Image requests account for {image_pct:.{args.precision}f}% of all requests")

    best = pick_most_popular_browser(stats["browser_counts"])
    if best is None:
        print("Most popular browser: (no recognized browsers found)")
    else:
        bname, bcount = best
        print(f"Most popular browser: {bname} with {bcount} hits")

    # Extra credit:
    hour_counts = stats["hour_counts"]
    # Create list of (hour, count) and sort by count desc, hour asc
    sorted_hours = sorted(hour_counts.items(), key=lambda x: (-x[1], x[0]))
    for hour, count in sorted_hours:
        # Leading zero for single digit hours to match expected format (e.g., "Hour 03")
        print(f"Hour {hour:02d} has {count} hits")

if __name__ == "__main__":
    main()