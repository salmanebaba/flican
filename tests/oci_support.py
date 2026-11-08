"""Small, self-contained OCI layouts for contract and native-scanner tests."""

import gzip
import hashlib
import io
import json
import tarfile


def make_oci(path, *, user="65532", files=None, layers=None, mutate=None):
    filesystem_layers = layers if layers is not None else [files or {"hello.txt": b"hello\n"}]
    blobs, descriptors, diff_ids = {}, [], []
    for files in filesystem_layers:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                if isinstance(content, tuple):
                    info.type, info.linkname = content
                    archive.addfile(info)
                else:
                    info.mode = 0o644
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
        raw = output.getvalue()
        diff_ids.append("sha256:" + hashlib.sha256(raw).hexdigest())
        compressed = gzip.compress(raw, mtime=0)
        digest = hashlib.sha256(compressed).hexdigest()
        blobs[digest] = compressed
        descriptors.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            "digest": "sha256:" + digest, "size": len(compressed)})
    config = {"architecture": "amd64", "os": "linux", "config": {"User": user},
              "rootfs": {"type": "layers", "diff_ids": diff_ids}}
    config_data = json.dumps(config).encode()
    config_digest = hashlib.sha256(config_data).hexdigest()
    blobs[config_digest] = config_data
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": len(config_data),
                           "digest": "sha256:" + config_digest}, "layers": descriptors}
    data = json.dumps(manifest).encode()
    manifest_digest = hashlib.sha256(data).hexdigest()
    blobs[manifest_digest] = data
    index = {"schemaVersion": 2, "manifests": [{"mediaType": manifest["mediaType"], "size": len(data),
                                              "digest": "sha256:" + manifest_digest}]}
    members = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}', "index.json": json.dumps(index).encode(),
               **{"blobs/sha256/" + key: value for key, value in blobs.items()}}
    if mutate:
        mutate(members)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return {"config_digest": "sha256:" + config_digest, "manifest_digest": "sha256:" + manifest_digest}
