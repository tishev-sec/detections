#!/usr/bin/env python3
"""Build the detection index and the docs site from detections/*/*/README.md front matter.

    python3 scripts/build.py          # update README.md index + generate docs/
    python3 scripts/build.py --check  # CI: fail on missing metadata or a stale README index
"""
import re
import shutil
import sys
from pathlib import Path

import yaml

REPO = "tishev-sec/detections"
ROOT = Path(__file__).resolve().parent.parent
DETECTIONS = ROOT / "detections"
DOCS = ROOT / "docs"
REQUIRED = ["id", "title", "platform", "data_source", "attack", "status", "date"]
FILES = [("sentinel.kql", "KQL (Sentinel / Defender XDR)", "kusto"), ("rule.yml", "Sigma", "yaml")]
START, END = "<!-- INDEX:START -->", "<!-- INDEX:END -->"


def load():
    dets, errors = [], []
    for readme in sorted(DETECTIONS.glob("*/*/README.md")):
        folder = readme.parent
        rel = folder.relative_to(ROOT).as_posix()
        m = re.match(r"^---\n(.*?)\n---\n(.*)$", readme.read_text(), re.S)
        if not m:
            errors.append(f"{rel}: README.md has no front matter")
            continue
        meta = yaml.safe_load(m.group(1)) or {}
        missing = [k for k in REQUIRED if not meta.get(k)]
        if missing:
            errors.append(f"{rel}: missing {', '.join(missing)}")
        if not folder.name.startswith(str(meta.get("id", "?"))):
            errors.append(f"{rel}: folder name must start with its id ({meta.get('id')})")
        if not any((folder / f).exists() for f, _, _ in FILES):
            errors.append(f"{rel}: needs sentinel.kql and/or rule.yml")
        meta.update(folder=folder, rel=rel, body=m.group(2), category=folder.parent.name)
        dets.append(meta)
    return sorted(dets, key=lambda d: str(d["id"])), errors


def attack_links(ids):
    return ", ".join(f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in ids)


def index_table(dets, link):
    rows = ["| ID | Detection | Category | Platform | ATT&CK | Formats | Status |",
            "|---|---|---|---|---|---|---|"]
    for d in dets:
        formats = " · ".join(n.split(" ")[0] for f, n, _ in FILES if (d["folder"] / f).exists())
        rows.append(f"| {d['id']} | [{d['title']}]({link(d)}) | {d['category']} | {d['platform']} | "
                    f"{attack_links(d['attack'])} | {formats} | {d['status']} |")
    return "\n".join(rows)


def render_readme(dets):
    text = (ROOT / "README.md").read_text()
    table = index_table(dets, lambda d: d["rel"] + "/")
    return re.sub(f"{START}.*?{END}", f"{START}\n{table}\n{END}", text, flags=re.S)


def build_docs(dets, readme):
    out = DOCS / "detections"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    blob = f"https://github.com/{REPO}/blob/main"
    for d in dets:
        # Relative links in a detection README point at files next to it; send them to GitHub.
        body = re.sub(r"\]\((?!https?:|#|mailto:)([^)]+)\)", lambda m: f"]({blob}/{d['rel']}/{m.group(1)})", d["body"])
        parts = [body.rstrip(), "", "## Rules", ""]
        for f, name, lang in FILES:
            if (d["folder"] / f).exists():
                parts += [f"### {name}", "", f"[View on GitHub]({blob}/{d['rel']}/{f})", "",
                          f"```{lang}", (d["folder"] / f).read_text().rstrip(), "```", ""]
        if d.get("linkedin"):
            parts += [f"[Discussion on LinkedIn]({d['linkedin']})", ""]
        (out / f"{d['folder'].name}.md").write_text("\n".join(parts))
    home = re.sub(f"{START}.*?{END}", index_table(dets, lambda d: f"detections/{d['folder'].name}.md"),
                  readme, flags=re.S)
    home = re.sub(r"\]\((?!https?:|#|mailto:|detections/DET)([^)]+)\)", lambda m: f"]({blob}/{m.group(1)})", home)
    (DOCS / "index.md").write_text(home)


def main():
    dets, errors = load()
    readme = render_readme(dets)
    if "--check" in sys.argv:
        if readme != (ROOT / "README.md").read_text():
            errors.append("README.md index is stale: run python3 scripts/build.py and commit")
        for e in errors:
            print(f"ERROR {e}")
        print(f"{len(dets)} detections, {len(errors)} errors")
        sys.exit(1 if errors else 0)
    for e in errors:
        print(f"WARN {e}")
    (ROOT / "README.md").write_text(readme)
    build_docs(dets, readme)
    print(f"Built {len(dets)} detections")


if __name__ == "__main__":
    main()
