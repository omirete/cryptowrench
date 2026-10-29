"""Install project-local official CUDA components and fetch pinned BitCrack sources.

Run from the repo: uv run python -m bitcoin_puzzle.setup_cuda
Downloads stay in .local; no drivers, registry settings, or global PATH are changed.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
LOCAL = ROOT / ".local"
LOCK = json.loads((ROOT / "native" / "upstream.json").read_text())
COMPONENTS = {
    "cuda_nvcc-windows-x86_64-12.8.93-archive": "9fdc70b4271ed9aad4d64cd7076a7d96ec36512d074b9995fe638de669197391",
    "cuda_cudart-windows-x86_64-12.8.90-archive": "4a39058fd8519444a81cfc7ae055d136f48d1a31ffa41ae255b35b2edd61e13b",
    "cuda_cccl-windows-x86_64-12.8.90-archive": "bd8548fa1ae82f92910bebc3079e14bd58c5a92aa64596d46bd610a478cb39d7",
}


def download(url, path, digest=None):
    if not path.exists() or (digest and hashlib.sha256(path.read_bytes()).hexdigest() != digest):
        print(f"Downloading {url}", flush=True)
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        temporary = path.with_suffix(".part")
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
        if digest and hashlib.sha256(temporary.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"Checksum mismatch for {url}")
        temporary.replace(path)
    return path


def extract(archive, destination):
    with zipfile.ZipFile(archive) as contents:
        for entry in contents.infolist():
            if not (destination / entry.filename).resolve().is_relative_to(destination.resolve()):
                raise RuntimeError("Archive entry outside destination")
        contents.extractall(destination)


def prepare():
    downloads = LOCAL / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    toolkit = LOCAL / "cuda"
    for name, digest in COMPONENTS.items():
        component = name.split("-windows")[0]
        url = f"https://developer.download.nvidia.com/compute/cuda/redist/{component}/windows-x86_64/{name}.zip"
        archive = download(url, downloads / f"{name}.zip", digest)
        unpacked = LOCAL / "components" / name
        if not unpacked.exists():
            extract(archive, LOCAL / "components")
        shutil.copytree(unpacked, toolkit, dirs_exist_ok=True)
    revision = LOCK["revision"]
    source = LOCAL / f"BitCrack-{revision}"
    archive = download(f"https://codeload.github.com/brichard19/BitCrack/zip/{revision}",
                       downloads / f"BitCrack-{revision}.zip", LOCK["archive_sha256"])
    if not source.exists():
        extract(archive, LOCAL)
    print(f"CUDA toolkit: {toolkit}\nPinned BitCrack source: {source}", flush=True)
    return toolkit, source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-only", action="store_true")
    args = parser.parse_args()
    toolkit, source = prepare()
    if not args.download_only:
        from .native_build import build
        build(toolkit, source)


if __name__ == "__main__":
    main()
