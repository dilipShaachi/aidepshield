"""
AIDepShield V2 — Requirements.txt parser.
"""

from typing import List
from app.data.models import PackageInput


def parse_requirements(req_text: str) -> List[PackageInput]:
    """Parse requirements.txt content into PackageInput list."""
    packages = []
    for line in req_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle version specifiers
        for sep in ["==", ">=", "<=", "~=", "!="]:
            if sep in line:
                name, version = line.split(sep, 1)
                # Strip extras like [standard]
                name = name.split("[")[0].strip()
                packages.append(PackageInput(name=name, version=version.strip()))
                break
        else:
            name = line.split("[")[0].strip()
            packages.append(PackageInput(name=name, version=None))
    return packages
