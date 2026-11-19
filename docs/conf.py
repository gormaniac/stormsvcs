"""Sphinx config for the stormsvcs documentation site.

Don't run sphinx-build on this folder directly: scripts/build_docs.py stages it with every
service's docs (svcs/<svc>/docs/) and the generated services.md and _services.json first.
The theme and its options match StormLib++ and docs.gormo.co, which serves this site at
https://docs.gormo.co/stormsvcs/.
"""

import json
import pathlib

project = "stormsvcs"
copyright = "2026, John Gorman"
author = "John Gorman"

REPO = "https://github.com/gormaniac/stormsvcs"

extensions = [
    "myst_parser",
    "sphinx.ext.extlinks",
]

exclude_patterns = ["_build", "**/__pycache__"]

html_theme = "shibuya"
html_static_path = ["_static"]
html_title = "Storm Services Docs"
html_baseurl = "https://docs.gormo.co/stormsvcs/"
html_copy_source = False
html_show_sourcelink = False

myst_enable_extensions = ["colon_fence", "deflist", "fieldlist"]
# Lets pages link to any heading up to ### with [text](page.md#the-heading-slug).
myst_heading_anchors = 3

# {src}`svcs/vt/src/vtsvc/svc.py` links a file in the repo, {gh}`55` a PR or issue.
extlinks = {
    "src": (f"{REPO}/blob/main/%s", "%s"),
    "gh": (f"{REPO}/issues/%s", "#%s"),
}

# The services the build staged, for the header's Services menu.
_svcs = pathlib.Path(__file__).with_name("_services.json")
SERVICES = json.loads(_svcs.read_text()) if _svcs.is_file() else []

_socials = [
    {"name": "GitHub", "url": REPO, "icon": "simple-icons:github"},
]

html_theme_options = {
    "accent_color": "teal",
    "color_mode": "auto",
    "nav_socials": _socials,
    "foot_socials": _socials,
    "nav_links": [
        {
            "title": "Services",
            "children": [
                {"title": s["name"], "url": f"{s['key']}/index", "summary": s["summary"]}
                for s in SERVICES
            ],
        },
        {"title": "Developers", "url": "dev/index"},
        {"title": "StormLib++", "url": "https://docs.gormo.co/stormlibpp/", "external": True},
    ],
}
