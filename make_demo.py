#!/usr/bin/env python3
# рисует svg из живого вывода main.py — типа скрин терминала
# svg печатает в stdout, сохраняйте перенаправлением: python make_demo.py > docs/demo.svg
import subprocess, html

out = subprocess.run(
    ["python", "main.py", "pip", "--min", "critical", "--limit", "3"],
    capture_output=True, text=True).stdout

lines = out.rstrip().splitlines()
lh = 18
w = 780
h = 48 + lh * len(lines) + 16

svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">' % (w, h, w, h)]
svg.append('<rect width="%d" height="%d" rx="8" fill="#0d1117"/>' % (w, h))
for c in ("#ff5f56", "#ffbd2e", "#27c93f"):
    svg.append('<circle cx="24" cy="24" r="6" fill="%s"/>' % c)
svg.append('<text x="50%%" y="28" text-anchor="middle" font-family="monospace" font-size="12" fill="#8b949e">cvedigest — pip --min critical</text>')
svg.append('<text x="20" y="56" font-family="Consolas,monospace" font-size="13" fill="#c9d1d9">$ python main.py pip --min critical --limit 3</text>')

y = 56 + lh
for ln in lines:
    color = "#c9d1d9"
    if "CRITICAL" in ln:
        color = "#f85149"
    elif "HIGH" in ln:
        color = "#d29922"
    elif ln.strip().startswith("- pip") or ln.strip().startswith("CVE"):
        color = "#8b949e"
    elif ln.strip().startswith("->"):
        color = "#58a6ff"
    svg.append('<text x="20" y="%d" font-family="Consolas,monospace" font-size="13" fill="%s">%s</text>'
               % (y, color, html.escape(ln)))
    y += lh
svg.append('</svg>')
print("\n".join(svg))
