#!/usr/bin/env python3
"""
Compatibility table from the e2e results.

  tests/report.py DIR

DIR holds one sub-directory per tested target (the CI artifacts
`eptracer-<suite>-<target>`), each with the results.tsv written by
tests/e2e/run.sh or tests/android/run.sh. Prints a Markdown table per suite,
targets as rows and scenarios as columns, for $GITHUB_STEP_SUMMARY and the
README.
"""
import os
import sys

ICON = {"PASS": "✅", "FAIL": "❌", "SKIP": "➖"}
SUITES = [("kernel", "Linux kernels (little-vm-helper VMs, x86_64)"),
          ("distro", "Linux distributions (host kernel, privileged containers)"),
          ("android", "Android emulator (x86_64, Google APIs images)")]


def load(root):
    data = {}
    for d in sorted(os.listdir(root)):
        tsv = os.path.join(root, d, "results.tsv")
        if not d.startswith("eptracer-") or not os.path.isfile(tsv):
            continue
        suite, _, target = d[len("eptracer-"):].partition("-")
        rows = {}
        with open(tsv) as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2:
                    rows[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "")
        data.setdefault(suite, {})[target] = rows
    return data


def main():
    data = load(sys.argv[1])
    failed = False
    for suite, title in SUITES:
        targets = data.get(suite)
        if not targets:
            continue
        cols = []
        for rows in targets.values():
            for k in rows:
                if k not in cols:
                    cols.append(k)
        print(f"### {title}\n")
        print("| target | " + " | ".join(cols) + " |")
        print("|---|" + "---|" * len(cols))
        for target, rows in targets.items():
            cells = []
            for c in cols:
                st = rows.get(c, ("", ""))[0]
                failed |= st == "FAIL"
                cells.append(ICON.get(st, " "))
            print(f"| `{target}` | " + " | ".join(cells) + " |")
        print()
    print("✅ pass · ❌ fail · ➖ skipped (tool not available on that target) · "
          "on kernels below 5.10 `check` passes when ePtracer refuses to run")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
