#!/usr/bin/env python3
"""Import a schema-v1 (prettyjws) Docker Hub image into the local docker as a tag.

Modern daemons refuse v1 manifests, and no mirror keeps ancient tags
(ubuntu:13.04). This fetches the signed manifest, downloads the fsLayer blobs
in bottom-up order, unpacks them into one rootfs and `docker import`s it.
usage: import-v1.py <library-name>:<tag> <final-tag>
"""
import json
import os
import subprocess
import sys
import tarfile
import urllib.request

REF = sys.argv[1]          # e.g. library/ubuntu:13.04
FINAL = sys.argv[2]        # e.g. ubuntu:13.04
repo, tag = REF.split(":")

def get(url, token=None, accept=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if accept:
        req.add_header("Accept", accept)
    return urllib.request.urlopen(req, timeout=120)

tok = json.load(get("https://auth.docker.io/token?service=registry.docker.io"
                    f"&scope=repository:{repo}:pull"))["token"]
man = json.load(get(f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}",
                    tok, "application/vnd.docker.distribution.manifest.v1+prettyjws"))
layers = [l["blobSum"] for l in man["fsLayers"]]        # newest first
print(f"manifest v1: {len(layers)} layers")

root = "/tmp/v1-root"
os.makedirs(root, exist_ok=True)
for i, blob in enumerate(reversed(layers), 1):          # oldest first
    cache = f"/tmp/v1-{blob.split(':')[1]}.tgz"
    if not os.path.exists(cache):
        with get(f"https://registry-1.docker.io/v2/{repo}/blobs/{blob}", tok) as r, open(cache, "wb") as f:
            f.write(r.read())
    print(f"layer {i}/{len(layers)}: {blob[:19]} ({os.path.getsize(cache)//1024} KiB)")
    with tarfile.open(cache, "r:gz") as t:
        t.extractall(root, filter="tar")                # no sanitize: distro rootfs

tarpath = f"/tmp/{FINAL.replace('/', '_').replace(':', '_')}.tar"
with tarfile.open(tarpath, "w") as t:
    t.add(root, arcname="")
print("rootfs tar:", os.path.getsize(tarpath) // (1024 * 1024), "MiB")
subprocess.run(["docker", "import", tarpath, FINAL], check=True)
print(f"imported as {FINAL}")
