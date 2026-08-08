#!/usr/bin/env python3
"""Konwersja kompendium Markdown -> kompletna, samodzielna strona HTML."""
import re
from pathlib import Path

import markdown

ROOT = Path(__file__).parent

STYLE = """
:root {
  --bg: #0d1117;
  --bg-alt: #161b22;
  --bg-code: #1c2128;
  --fg: #e6edf3;
  --fg-dim: #9da7b3;
  --accent: #e5484d;
  --accent-dim: #b33a3e;
  --border: #30363d;
  --link: #ff6b70;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: 70px; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.7;
}
.topbar {
  position: sticky; top: 0; z-index: 100;
  background: rgba(13,17,23,.95);
  backdrop-filter: blur(6px);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
  display: flex; align-items: center; gap: 14px;
}
.topbar .logo { color: var(--accent); font-weight: 800; font-size: 18px; letter-spacing: .5px; white-space: nowrap; }
.topbar nav { display: flex; gap: 4px; overflow-x: auto; scrollbar-width: thin; }
.topbar nav a {
  color: var(--fg-dim); text-decoration: none; font-size: 13px;
  padding: 4px 10px; border-radius: 6px; white-space: nowrap;
}
.topbar nav a:hover { color: var(--fg); background: var(--bg-alt); }
.topbar .lang-switch {
  margin-left: auto; flex-shrink: 0;
  color: var(--fg); text-decoration: none; font-size: 13px; font-weight: 600;
  padding: 4px 10px; border-radius: 6px; border: 1px solid var(--border);
  white-space: nowrap;
}
.topbar .lang-switch:hover { background: var(--bg-alt); border-color: var(--accent-dim); }
.hero {
  max-width: 900px; margin: 0 auto; padding: 48px 24px 24px;
  border-bottom: 1px solid var(--border);
}
.hero .badge {
  display: inline-block; background: var(--accent); color: #fff;
  font-size: 12px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 1px; padding: 4px 12px; border-radius: 4px; margin-bottom: 16px;
}
.hero h1 { margin: 0 0 8px; font-size: 2.2rem; line-height: 1.2; }
.hero p.sub { color: var(--fg-dim); margin: 0; }
.disclaimer {
  max-width: 900px; margin: 24px auto 0; padding: 0 24px;
}
.disclaimer .box {
  border: 1px solid var(--accent-dim); border-left: 4px solid var(--accent);
  background: rgba(229,72,77,.08); border-radius: 8px;
  padding: 14px 18px; font-size: 14px; color: var(--fg-dim);
}
main { max-width: 900px; margin: 0 auto; padding: 24px 24px 80px; }
h1 { display: none; } /* tytul w hero */
h2 {
  margin-top: 56px; padding-top: 12px; padding-bottom: 8px;
  border-bottom: 2px solid var(--accent-dim);
  font-size: 1.6rem;
}
h3 { margin-top: 36px; color: var(--accent); font-size: 1.2rem; }
h4 { margin-top: 24px; }
a { color: var(--link); }
img {
  max-width: 100%; height: auto; display: block; margin: 20px auto;
  border: 1px solid var(--border); border-radius: 8px; background: #fff;
}
table { border-collapse: collapse; width: 100%; margin: 20px 0; font-size: 14px; display: block; overflow-x: auto; }
th, td { border: 1px solid var(--border); padding: 8px 12px; text-align: left; vertical-align: top; }
th { background: var(--bg-alt); color: var(--accent); }
tr:nth-child(even) td { background: rgba(255,255,255,.02); }
code {
  background: var(--bg-code); border: 1px solid var(--border);
  border-radius: 4px; padding: 1px 6px;
  font-family: "JetBrains Mono", "Fira Code", Consolas, monospace; font-size: .9em;
}
pre {
  background: var(--bg-code); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px; overflow-x: auto;
}
pre code { background: none; border: none; padding: 0; }
blockquote {
  margin: 16px 0; padding: 4px 18px;
  border-left: 4px solid var(--accent-dim);
  background: var(--bg-alt); border-radius: 0 8px 8px 0;
  color: var(--fg-dim);
}
sup { color: var(--accent); font-size: .75em; }
hr { border: none; border-top: 1px solid var(--border); margin: 40px 0; }
ul li, ol li { margin: 4px 0; }
footer {
  border-top: 1px solid var(--border);
  padding: 24px; text-align: center;
  color: var(--fg-dim); font-size: 13px;
}
@media (max-width: 700px) {
  .hero h1 { font-size: 1.5rem; }
  h2 { font-size: 1.3rem; }
}
"""

PAGES = [
    dict(
        lang="pl",
        md_file="Red Team na Windows - kompendium.md",
        out_file="index.html",
        title="Red Team na Windows — kompendium wiedzy ofensywnej i detekcyjnej",
        description="Kompletna ścieżka operacji red team w środowiskach Windows i Active Directory: rekonesans, eskalacja uprawnień, persistence, ruch boczny, dominacja domeny, C2, detekcja.",
        badge="Kompendium &middot; sierpień 2026",
        hero_title="Red Team na Windows",
        hero_sub="Kompletna ścieżka operacji ofensywnej w Windows i Active Directory: metodologia, techniki, narzędzia, infrastruktura C2 i kontrapunkt detekcyjny — zmapowane na MITRE ATT&amp;CK.",
        disclaimer_label="Zastrzeżenie:",
        disclaimer_text="materiał wyłącznie do celów edukacyjnych, autoryzowanych testów bezpieczeństwa i budowania detekcji. Użycie opisanych technik na systemach bez pisemnej zgody właściciela stanowi przestępstwo (m.in. art. 267–269 KK).",
        footer="Red Team na Windows — kompendium wiedzy ofensywnej i detekcyjnej &middot; stan na sierpień 2026",
    ),
]

for page in PAGES:
    md_path = ROOT / page["md_file"]
    text = md_path.read_text(encoding="utf-8")

    # Przypisy bibliograficzne w formacie [^19^] -> <sup>[19]</sup>
    text = re.sub(r"\[\^(\d+)\^\]", r"<sup>[\1]</sup>", text)

    body = markdown.markdown(
        text,
        extensions=["tables", "fenced_code", "toc", "attr_list"],
        extension_configs={"toc": {"slugify": lambda v, s: re.sub(r"[^\w-]", "", v.lower().replace(" ", "-"))}},
    )

    # Spis tresci z naglowkow h2
    sections = re.findall(r'<h2 id="([^"]+)">(.+?)</h2>', body)
    toc_links = "\n".join(
        f'<a href="#{sid}">{re.sub(r"<[^>]+>", "", title)}</a>' for sid, title in sections
    )

    html = f"""<!DOCTYPE html>
<html lang="{page['lang']}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{page['title']}</title>
<meta name="description" content="{page['description']}">
<style>{STYLE}</style>
</head>
<body>
<header class="topbar">
  <span class="logo">RT//WINDOWS</span>
  <nav>
    {toc_links}
  </nav>
</header>
<section class="hero">
  <span class="badge">{page['badge']}</span>
  <h1>{page['hero_title']}</h1>
  <p class="sub">{page['hero_sub']}</p>
</section>
<div class="disclaimer">
  <div class="box">
    <strong>{page['disclaimer_label']}</strong> {page['disclaimer_text']}
  </div>
</div>
<main>
{body}
</main>
<footer>
  {page['footer']}
</footer>
</body>
</html>
"""

    out_path = ROOT / page["out_file"]
    out_path.write_text(html, encoding="utf-8")
    print(f"OK: {out_path} ({out_path.stat().st_size} B), sekcji w TOC: {len(sections)}")
