# Pinned tools

Everything installed on the build VM from outside the repo is pinned to a version and verified before it runs.

| Tool | Version | Source | Verified against |
|---|---|---|---|
| kubectl | v1.35.5 | dl.k8s.io | published sha256 `90f75ea6ecc9ea5633262e1c0b83a40560003b30fc94a04cb099404fcef0c224` |
| k3d | v5.9.0 | GitHub release | `checksums.txt` sha256 `06d8f25bc3a971c4eb29e0ff08429b180402db0f4dec838c9eac427e296800a0` |
| kubernetes-mcp-server | 0.1.1 (npm) | npm registry, installed with `--ignore-scripts` | npm integrity `sha512-C+kFGGDOiVSiYSbCzdT/sL33+pbSRJ+2EHre+GuXI9wSFmFCjrMKIelwcRPZaFUGbYxfZQjRhxPjgig8B71DGw==` |
| Switch (server and controller) | 0.31.0 | GitHub release | image tag pinned in `.env` |

kubectl 1.35.5 matches the cluster's Kubernetes (k3s v1.35.5): kubectl supports one minor version of skew, so the newest kubectl would not be supported.
kubernetes-mcp-server 0.1.2 exists as a GitHub tag but is not on npm, so 0.1.1 is used.
An unpinned `npx ...@latest` is never used.
