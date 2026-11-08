"""Read and verify a single-platform OCI archive without extracting or executing it."""

import gzip
import hashlib
import json
import re
import tarfile
import zlib
from pathlib import Path, PurePosixPath

from flican.core.artifacts import MAX_IMAGE_BYTES, file_digest

MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
LAYER_TYPES = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip",
               "application/vnd.docker.image.rootfs.diff.tar.gzip"}
MAX_EXPANDED_BYTES = 4 * 1024 * 1024 * 1024


def materialize_layout(path: Path, destination: Path, image: dict) -> Path:
    """Copy verified OCI layout blobs only; never extract image filesystem layers."""
    required = {"oci-layout", "index.json", "blobs/sha256/" + image["manifest_digest"][7:],
                "blobs/sha256/" + image["config_digest"][7:]}
    required.update("blobs/sha256/" + layer["digest"][7:] for layer in image["layers"])
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    copied, total = set(), 0
    with tarfile.open(path, mode="r:") as archive:
        for number, member in enumerate(archive, 1):
            if number > 10000:
                raise ValueError("OCI layout contains too many members.")
            name = _name(member.name)
            if name not in required:
                continue
            if name in copied or not member.isfile() or not 0 <= member.size <= MAX_IMAGE_BYTES:
                raise ValueError("Invalid OCI layout member.")
            total += member.size
            if total > MAX_IMAGE_BYTES:
                raise ValueError("OCI layout exceeds its size limit.")
            target = destination / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open("xb") as output:
                target.chmod(0o600)
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
            if name.startswith("blobs/sha256/") and file_digest(target, MAX_IMAGE_BYTES) != name.rsplit("/", 1)[1]:
                raise ValueError("OCI layout copy failed its digest check.")
            copied.add(name)
    if copied != required:
        raise ValueError("Required OCI blobs are missing.")
    return destination


def _name(value: str) -> str:
    while value.startswith("./"):
        value = value[2:]
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or any(ord(c) < 32 for c in value):
        raise ValueError("OCI archive contains unsafe member paths.")
    return path.as_posix()


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("OCI JSON contains duplicate keys.")
        value[key] = item
    return value


def _json(content: bytes) -> dict:
    value = json.loads(content, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError("OCI JSON must be an object.")
    return value


class _LayerReader:
    def __init__(self, stream, budget):
        self.stream, self.budget = stream, budget
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        if size < 0:
            raise ValueError("Unbounded image-layer reads are not allowed.")
        content = self.stream.read(size)
        self.budget[0] += len(content)
        if self.budget[0] > MAX_EXPANDED_BYTES:
            raise ValueError("Expanded image layers exceed the 4 GiB analysis limit.")
        self.digest.update(content)
        return content


def inspect_oci(path: Path) -> dict:
    archive_hash = file_digest(path, MAX_IMAGE_BYTES)
    try:
        with tarfile.open(path, mode="r:") as archive:
            members = {}
            for number, member in enumerate(archive, 1):
                if number > 10000:
                    raise ValueError("OCI layout contains too many members.")
                name = _name(member.name)
                if member.isdir():
                    continue
                if not member.isfile() or name in members or len(members) >= 10000:
                    raise ValueError("OCI layout members must be unique regular files.")
                members[name] = member

            def read(name, limit=4 * 1024 * 1024):
                member = members.get(name)
                if member is None or member.size > limit:
                    raise ValueError("OCI archive is missing a required bounded member.")
                with archive.extractfile(member) as stream:
                    return stream.read(limit + 1)

            if _json(read("oci-layout")).get("imageLayoutVersion") != "1.0.0":
                raise ValueError("Unsupported OCI image layout version.")

            def blob(descriptor):
                if not isinstance(descriptor, dict):
                    raise ValueError("Invalid OCI descriptor.")
                digest = descriptor.get("digest")
                size = descriptor.get("size")
                if (not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                        or type(size) is not int or not 0 <= size <= MAX_IMAGE_BYTES):
                    raise ValueError("OCI descriptors require SHA-256 and a bounded byte size.")
                name = "blobs/sha256/" + digest[7:]
                member = members.get(name)
                if member is None or member.size != size:
                    raise ValueError("OCI blob is missing or has the wrong size.")
                with archive.extractfile(member) as stream:
                    observed = hashlib.file_digest(stream, "sha256").hexdigest()
                if observed != digest[7:]:
                    raise ValueError("OCI blob digest verification failed.")
                return name

            index = _json(read("index.json"))
            descriptors = index.get("manifests")
            if type(index.get("schemaVersion")) is not int or index["schemaVersion"] != 2 or not isinstance(descriptors, list):
                raise ValueError("Invalid OCI image index.")
            if len(descriptors) != 1 or descriptors[0].get("mediaType") not in MANIFEST_TYPES:
                raise ValueError("Export exactly one image platform without extra attestations for this OCI scanner.")
            descriptor = descriptors[0]
            manifest = _json(read(blob(descriptor)))
            if type(manifest.get("schemaVersion")) is not int or manifest["schemaVersion"] != 2:
                raise ValueError("Unsupported OCI image manifest.")
            config_descriptor = manifest.get("config")
            config = _json(read(blob(config_descriptor)))
            if config.get("os") != "linux" or config.get("architecture") not in ("amd64", "arm64"):
                raise ValueError("Only single-platform Linux amd64/arm64 images are supported.")
            platform = descriptor.get("platform")
            if platform is not None and (not isinstance(platform, dict) or any(
                platform.get(key) != config[key] for key in ("os", "architecture")
            )):
                raise ValueError("OCI index platform does not match its image configuration.")
            runtime = config.get("config", {})
            layers = manifest.get("layers")
            rootfs = config.get("rootfs", {})
            diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
            if (not isinstance(runtime, dict) or not isinstance(layers, list) or len(layers) > 1024
                    or not isinstance(diff_ids, list) or len(diff_ids) != len(layers)
                    or rootfs.get("type") != "layers"):
                raise ValueError("OCI image layers and rootfs do not agree.")
            passwd, budget, layer_info, etc_unresolved = None, [0], [], False
            for layer, diff_id in zip(layers, diff_ids, strict=True):
                if (not isinstance(layer, dict) or layer.get("mediaType") not in LAYER_TYPES
                        or not isinstance(diff_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", diff_id)):
                    raise ValueError("Unsupported OCI layer compression or rootfs digest.")
                name = blob(layer)
                new_passwd, seen_passwd, reset = None, False, False
                new_etc, reset_etc = None, False
                with archive.extractfile(members[name]) as raw:
                    stream = gzip.GzipFile(fileobj=raw) if layer["mediaType"].endswith(("+gzip", ".gzip")) else raw
                    reader = _LayerReader(stream, budget)
                    with tarfile.open(fileobj=reader, mode="r|") as filesystem:
                        count = 0
                        for entry in filesystem:
                            count += 1
                            if count > 100000 or entry.size < 0:
                                raise ValueError("OCI layer has too many filesystem entries.")
                            filename = _name(entry.name)
                            if filename in ("etc/.wh.passwd", "etc/.wh..wh..opq", ".wh.etc", ".wh..wh..opq"):
                                reset = True
                            if filename in (".wh.etc", ".wh..wh..opq"):
                                reset_etc = True
                            if filename == "etc":
                                new_etc = not entry.isdir()
                                if new_etc:
                                    reset = True
                            if filename == "etc/passwd":
                                if seen_passwd:
                                    raise ValueError("Duplicate /etc/passwd in one image layer.")
                                seen_passwd = True
                                if entry.isfile() and entry.size <= 1024 * 1024:
                                    new_passwd = filesystem.extractfile(entry).read()
                    while reader.read(128 * 1024):
                        pass
                    if "sha256:" + reader.digest.hexdigest() != diff_id:
                        raise ValueError("OCI uncompressed layer digest verification failed.")
                    if stream is not raw:
                        stream.close()
                if reset:
                    passwd = None
                # Whiteouts remove lower-layer entries, regardless of their order in this tar.
                if reset_etc:
                    etc_unresolved = False
                if new_etc is not None:
                    etc_unresolved = new_etc
                if seen_passwd:
                    passwd = new_passwd
                layer_info.append({"digest": layer["digest"], "size": layer["size"], "diff_id": diff_id})
            user = runtime.get("User", "")
            if not isinstance(user, str) or len(user) > 256 or any(ord(c) < 32 for c in user):
                raise ValueError("Invalid OCI runtime User configuration.")
            name = user.split(":", 1)[0]
            uid = 0 if not name else (int(name) if name.isascii() and name.isdigit() else None)
            if uid is None and passwd is not None and not etc_unresolved:
                try:
                    matches = [line.split(":")[2] for line in passwd.decode("utf-8").splitlines()
                               if len(line.split(":")) >= 7 and line.split(":")[0] == name]
                    if len(matches) == 1 and matches[0].isascii() and matches[0].isdigit():
                        uid = int(matches[0])
                except UnicodeError:
                    pass
            if uid is not None and not 0 <= uid < 2**32 - 1:
                uid = None
            return {"schema_version": 1, "archive_sha256": archive_hash,
                    "manifest_digest": descriptor["digest"], "config_digest": config_descriptor["digest"],
                    "platform": f"linux/{config['architecture']}", "runtime_user": user,
                    "resolved_uid": uid, "user_status": "unresolved" if uid is None else ("root" if uid == 0 else "nonroot"),
                    "layers": layer_info, "expanded_bytes": budget[0]}
    except (tarfile.TarError, EOFError, KeyError, TypeError, AttributeError, OSError, zlib.error) as error:
        raise ValueError("Invalid or unsupported OCI archive.") from error
