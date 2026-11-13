#!/usr/bin/env python3
"""Machine-readable receipt for the published Mesh keep-server image.

  mesh_image_receipt.py build  --out R --publish P --pulled U --config C \
                               --elf E --version V --buildinfo B
  mesh_image_receipt.py verify R --source-sha SHA [--registry-image REPO]

`build` runs in CI after the image was pulled back by its digest. It reads
only facts (JSON/text files and four CI variables), checks them against each
other and writes the receipt, or writes nothing and exits non-zero. Every
value that reaches the receipt is matched against a closed pattern; the
environment is never copied and nothing it holds is printed. `verify` re-checks
a receipt file, for the operator (docs/deploy.md).
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.dont_write_bytecode = True

SCHEMA = "keep-mesh-image-receipt/1"
VARIANT = "mesh"
PLATFORM = "linux/amd64"
MESH_MAIN = "github.com/entire-vc/evc-keep/plugins/mesh/cmd/keep-server"
ELF_PATH = "usr/local/bin/keep-server"
IMAGE_NAME = "keep-server-mesh"
USER = "10001:10001"
ENTRYPOINT = ["/usr/local/bin/keep-server"]
EM_X86_64 = 62

SHA40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
DIGITS = re.compile(r"[0-9]{1,18}")
# 2026-11-06T13:00:00+03:00 or ...Z, as CI_COMMIT_TIMESTAMP / date -u.
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})")
# host[:port]/path, lowercase, no tag, no digest.
REPOSITORY = re.compile(r"[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+")

TOP_KEYS = {"schema", "source_sha", "project", "pipeline_id", "publish_job_id", "pull_job_id",
            "receipt_job_id", "variant", "platform", "build_time", "image", "elf", "runtime"}
IMAGE_KEYS = {"repository", "tag", "reference", "digest", "by_digest"}
ELF_KEYS = {"path", "sha256", "main_package", "machine"}
RUNTIME_KEYS = {"commit", "build_time"}


class ReceiptError(Exception):
    """A fact is missing or contradicts another; the message names no value."""


def need(cond, why):
    if not cond:
        raise ReceiptError(why)


def fullmatch(pattern, value, what):
    need(isinstance(value, str) and pattern.fullmatch(value) is not None, f"{what} is malformed or missing")
    return value


def closed(obj, keys, what):
    need(isinstance(obj, dict), f"{what} is not an object")
    # Input key names are data, never echoed: only the count of strays is named.
    extra = len(set(obj) - keys)
    need(extra == 0, f"{what} has {extra} key(s) outside the closed list")
    missing = sorted(keys - set(obj))  # our own constants, safe to name
    need(not missing, f"{what} lacks keys: {missing}")


def validate_receipt(r, source_sha, registry_image):
    """Raise ReceiptError unless r is a consistent receipt for source_sha."""
    fullmatch(SHA40, source_sha, "expected source sha")
    need(isinstance(registry_image, str) and REPOSITORY.fullmatch(registry_image), "expected registry image is malformed")
    closed(r, TOP_KEYS, "receipt")
    need(r["schema"] == SCHEMA, "unknown schema")
    need(r["source_sha"] == source_sha, "receipt source sha is not the expected commit")
    fullmatch(re.compile(r"[a-z0-9._/-]+"), r["project"], "project")
    for key in ("pipeline_id", "publish_job_id", "pull_job_id", "receipt_job_id"):
        need(isinstance(r[key], int) and not isinstance(r[key], bool) and r[key] > 0, f"{key} is not a positive integer")
    need(r["variant"] == VARIANT, "variant is not mesh")
    need(r["platform"] == PLATFORM, "platform is not linux/amd64")
    fullmatch(TIMESTAMP, r["build_time"], "build_time")

    closed(r["image"], IMAGE_KEYS, "image")
    img = r["image"]
    need(img["repository"] == registry_image + "/" + IMAGE_NAME, "image is not in the project registry")
    need(img["tag"] == source_sha, "image tag is not the source sha")
    need(img["reference"] == img["repository"] + ":" + source_sha, "image reference does not name the source sha")
    fullmatch(DIGEST, img["digest"], "image digest")
    need(img["by_digest"] == img["repository"] + "@" + img["digest"], "by_digest does not match the digest")

    closed(r["elf"], ELF_KEYS, "elf")
    elf = r["elf"]
    need(elf["path"] == ELF_PATH, "elf path")
    fullmatch(HEX64, elf["sha256"], "elf sha256")
    need(elf["main_package"] == MESH_MAIN, "binary is not the Mesh variant")
    need(elf["machine"] == "x86_64", "binary is not x86_64")

    closed(r["runtime"], RUNTIME_KEYS, "runtime")
    need(r["runtime"]["commit"] == source_sha, "/version commit is not the source sha")
    need(r["runtime"]["build_time"] == r["build_time"], "/version build_time is not the build time")


def elf_machine(blob):
    """'x86_64' for a 64-bit little-endian x86-64 ELF, else a description."""
    need(len(blob) >= 20 and blob[:4] == b"\x7fELF", "binary is not an ELF file")
    need(blob[4] == 2 and blob[5] == 1, "binary is not 64-bit little-endian")
    machine = int.from_bytes(blob[18:20], "little")
    return "x86_64" if machine == EM_X86_64 else f"machine-{machine}"


def main_package(text):
    """The main package path from `go version -m` output."""
    for line in text.splitlines():
        parts = line.strip().split("\t")
        if len(parts) == 2 and parts[0] == "path":
            return parts[1]
    return ""


def read_json(path, what):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        raise ReceiptError(f"{what} is not readable JSON") from None
    need(isinstance(data, dict), f"{what} is not an object")
    return data


def env_value(name, pattern):
    return fullmatch(pattern, os.environ.get(name, ""), name)


def build(args):
    source_sha = env_value("CI_COMMIT_SHA", SHA40)
    registry_image = env_value("CI_REGISTRY_IMAGE", REPOSITORY)
    project = env_value("CI_PROJECT_PATH", re.compile(r"[a-z0-9._/-]+"))
    pipeline_id = int(env_value("CI_PIPELINE_ID", DIGITS))
    receipt_job = int(env_value("CI_JOB_ID", DIGITS))

    publish = read_json(args.publish, "publish record")
    closed(publish, {"source_sha", "pipeline_id", "job_id", "repository", "tag", "digest", "build_time"},
           "publish record")
    need(publish["source_sha"] == source_sha, "publish record is for another commit")
    need(publish["pipeline_id"] == str(pipeline_id), "publish record is from another pipeline")
    publish_job = int(fullmatch(DIGITS, publish["job_id"], "publish job id"))
    need(publish["repository"] == registry_image + "/" + IMAGE_NAME, "published outside the project registry")
    need(publish["tag"] == source_sha, "published tag is not the source sha")
    digest = fullmatch(DIGEST, publish["digest"], "published digest")
    build_time = fullmatch(TIMESTAMP, publish["build_time"], "build_time")

    pulled = read_json(args.pulled, "pull record")
    need(pulled.get("digest") == digest, "digest pulled back differs from the published one")
    need(pulled.get("tag_digest") == digest, "the tag no longer points at the published digest")
    pull_job = int(fullmatch(DIGITS, pulled.get("job_id"), "pull job id"))
    pulled_elf = fullmatch(HEX64, pulled.get("elf_sha256"), "pulled elf sha256")

    cfg = read_json(args.config, "image config")
    need(cfg.get("os") == "linux" and cfg.get("architecture") == "amd64", "image config is not linux/amd64")
    run = cfg.get("config")
    need(isinstance(run, dict), "image config has no run section")
    need(run.get("User") == USER, "image does not run as 10001:10001")
    need(run.get("Entrypoint") == ENTRYPOINT, "image entrypoint is not keep-server")

    with open(args.elf, "rb") as fh:
        blob = fh.read()
    machine = elf_machine(blob)
    elf_sha = hashlib.sha256(blob).hexdigest()
    need(elf_sha == pulled_elf, "binary hash differs from the one taken out of the pulled image")
    with open(args.buildinfo, encoding="utf-8", errors="replace") as fh:
        main_pkg = main_package(fh.read())

    version = read_json(args.version, "/version body")
    closed(version, {"commit", "build_time"}, "/version body")

    receipt = {
        "schema": SCHEMA,
        "source_sha": source_sha,
        "project": project,
        "pipeline_id": pipeline_id,
        "publish_job_id": publish_job,
        "pull_job_id": pull_job,
        "receipt_job_id": receipt_job,
        "variant": VARIANT,
        "platform": PLATFORM,
        "build_time": build_time,
        "image": {
            "repository": publish["repository"],
            "tag": source_sha,
            "reference": publish["repository"] + ":" + source_sha,
            "digest": digest,
            "by_digest": publish["repository"] + "@" + digest,
        },
        "elf": {"path": ELF_PATH, "sha256": elf_sha, "main_package": main_pkg, "machine": machine},
        "runtime": {"commit": version["commit"], "build_time": version["build_time"]},
    }
    validate_receipt(receipt, source_sha, registry_image)
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(receipt, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, args.out)
    print(f"receipt {receipt['image']['by_digest']} source {source_sha} elf {elf_sha}")


def verify(args):
    receipt = read_json(args.receipt, "receipt")
    registry_image = args.registry_image
    if registry_image is None:
        repo = receipt.get("image", {}).get("repository", "")
        need(isinstance(repo, str) and repo.endswith("/" + IMAGE_NAME), "image repository is malformed")
        registry_image = repo[: -len(IMAGE_NAME) - 1]
    validate_receipt(receipt, args.source_sha, registry_image)
    print("receipt ok", receipt["image"]["by_digest"])


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    for name in ("out", "publish", "pulled", "config", "elf", "version", "buildinfo"):
        b.add_argument("--" + name, required=True)
    v = sub.add_parser("verify")
    v.add_argument("receipt")
    v.add_argument("--source-sha", required=True)
    v.add_argument("--registry-image")
    args = ap.parse_args(argv)
    try:
        (build if args.cmd == "build" else verify)(args)
    except ReceiptError as err:
        print(f"FAIL mesh-image-receipt: {err}", file=sys.stderr)
        return 1
    except OSError as err:
        print(f"FAIL mesh-image-receipt: {type(err).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
