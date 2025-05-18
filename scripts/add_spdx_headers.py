#!/usr/bin/env python3
import os
import sys
from pathlib import Path

SPDX_HEADER_MAP = {
    ".rs": "// SPDX-License-Identifier: Apache-2.0\n",
    ".sh": "# SPDX-License-Identifier: Apache-2.0\n",
    ".py": "# SPDX-License-Identifier: Apache-2.0\n",
    ".js": "// SPDX-License-Identifier: Apache-2.0\n",
    ".ts": "// SPDX-License-Identifier: Apache-2.0\n",
    ".bash": "# SPDX-License-Identifier: Apache-2.0\n",
    ".zsh": "# SPDX-License-Identifier: Apache-2.0\n",
    "Dockerfile": "# SPDX-License-Identifier: Apache-2.0\n",
}

def insert_spdx_header(file_path, header, check=False):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.readlines()
        if any(header.strip() in line for line in content):
            return True  # Already present
        if check:
            print(f"❌ Missing SPDX header: {file_path}")
            return False
        if content and content[0].startswith("#!") and not file_path.name == "Dockerfile":
            content.insert(1, header)
        else:
            content.insert(0, header)
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(content)
        print(f"✔️  Added SPDX header to: {file_path}")
        return True
    except Exception as e:
        print(f"⚠️  Could not process {file_path}: {e}")
        return False

def main():
    check_mode = "--check" in sys.argv
    success = True
    for root, dirs, files in os.walk("."):
        for name in files:
            path = Path(root) / name
            suffix = path.suffix
            if name == "Dockerfile":
                header = SPDX_HEADER_MAP["Dockerfile"]
                ok = insert_spdx_header(path, header, check=check_mode)
            elif suffix in SPDX_HEADER_MAP:
                ok = insert_spdx_header(path, SPDX_HEADER_MAP[suffix], check=check_mode)
            else:
                continue
            if not ok and check_mode:
                success = False
    if check_mode and not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
