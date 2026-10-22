#!/usr/bin/env python3
"""Render a deliverable Markdown file to PDF through headless Chrome/Edge.

Markdown -> HTML (tables + fenced code) -> print-to-pdf. No LaTeX, no office
suite: the only external requirement is a Chromium-family browser, which every
Windows box already has. Chinese text is set in SimSun and ASCII in Times, the
same pairing the competition report uses, so the two documents look alike.

    python tools/export_pdf.py docs/deliverables/VULN_REPORT.md \
        --output docs/deliverables/VULN_REPORT.pdf [--title "标题"]

Exit codes: 0 ok, 1 renderer failed, 2 bad input.
"""
from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BROWSERS = (
    r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
    r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
)

CSS = """
@page { size: A4; margin: 18mm 16mm 18mm 16mm; }
html { -webkit-print-color-adjust: exact; }
body {
  font-family: "Times New Roman", SimSun, "Songti SC", serif;
  font-size: 10.5pt; line-height: 1.55; color: #111; margin: 0;
  text-align: justify;
}
h1 { font-size: 18pt; margin: 0 0 10pt; text-align: center; letter-spacing: 1pt; }
h2 { font-size: 14pt; margin: 16pt 0 8pt; padding-bottom: 3pt;
     border-bottom: 1px solid #999; page-break-after: avoid; }
h3 { font-size: 12pt; margin: 12pt 0 6pt; page-break-after: avoid; }
h4 { font-size: 11pt; margin: 10pt 0 5pt; page-break-after: avoid; }
p, li { margin: 4pt 0; }
ul, ol { margin: 4pt 0 4pt 0; padding-left: 18pt; }
code { font-family: Consolas, "Courier New", monospace; font-size: 9pt;
       background: #f4f4f4; padding: 0 1pt; }
pre { font-family: Consolas, "Courier New", monospace; font-size: 8.6pt;
      line-height: 1.35; background: #f7f7f7; border: 1px solid #ddd;
      border-left: 3px solid #999; padding: 6pt 8pt; margin: 6pt 0;
      white-space: pre-wrap; word-break: break-all; page-break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 8.6pt; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0; font-size: 8.8pt;
        page-break-inside: auto; }
thead { display: table-header-group; }
tr { page-break-inside: avoid; }
th, td { border: 0.6pt solid #888; padding: 3pt 4pt; vertical-align: top;
         text-align: left; word-break: break-word; }
/* 序号列不折行：A4 正文宽度下 "10" 会被拆成 "1 / 0" */
th:first-child, td:first-child { white-space: nowrap; }
th { background: #ececec; font-weight: bold; }
blockquote { margin: 6pt 0; padding: 4pt 8pt; border-left: 2pt solid #bbb;
             color: #333; background: #fafafa; }
hr { border: none; border-top: 0.6pt solid #ccc; margin: 10pt 0; }
a { color: #111; text-decoration: none; }
"""


def find_browser(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit if Path(explicit).is_file() else None
    for candidate in BROWSERS:
        if os.path.isfile(candidate):
            return candidate
    for name in ('chrome', 'msedge', 'chromium', 'google-chrome'):
        found = shutil.which(name)
        if found:
            return found
    return None


def md_to_html(text: str) -> str:
    try:
        import markdown
    except ImportError:
        raise SystemExit('需要 markdown 库: pip install markdown')
    return markdown.markdown(
        text,
        extensions=['tables', 'fenced_code', 'sane_lists', 'attr_list'],
        output_format='html5',
    )


def wrap(body: str, title: str) -> str:
    return (
        '<!DOCTYPE html>\n<html lang="zh-CN"><head><meta charset="utf-8">'
        f'<title>{html.escape(title)}</title><style>{CSS}</style></head>'
        f'<body>{body}</body></html>'
    )


def render(html_path: Path, pdf_path: Path, browser: str, timeout: int = 300):
    # --no-pdf-header-footer keeps the date/URL out of the margin; the document
    # already carries its own numbering in the text.
    cmd = [browser, '--headless=new', '--disable-gpu', '--no-sandbox',
           '--no-pdf-header-footer', '--run-all-compositor-stages-before-draw',
           '--virtual-time-budget=10000',
           f'--print-to-pdf={pdf_path}', html_path.as_uri()]
    completed = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, errors='replace')
    return completed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--title', default=None)
    parser.add_argument('--browser', default=None)
    args = parser.parse_args(argv)

    if not args.source.is_file():
        print(f'ERROR: no such file: {args.source}', file=sys.stderr)
        return 2
    text = args.source.read_text(encoding='utf-8')
    body = md_to_html(text)
    title = args.title or next(
        (line[2:].strip() for line in text.splitlines() if line.startswith('# ')),
        args.source.stem)

    browser = find_browser(args.browser)
    if not browser:
        print('ERROR: 未找到 Chrome/Edge，可用 --browser 指定', file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        html_path = Path(tmp) / 'doc.html'
        html_path.write_text(wrap(body, title), encoding='utf-8')
        completed = render(html_path, args.output.resolve(), browser)
    if not args.output.is_file() or args.output.stat().st_size < 1024:
        print('ERROR: 渲染未产出 PDF\n' + (completed.stderr or '')[-800:],
              file=sys.stderr)
        return 1
    size = args.output.stat().st_size / 1024
    print(f'{args.output}  {size:.0f} KiB  ({browser})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
