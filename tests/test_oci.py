import hashlib
import io
import json
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from oci_support import make_oci
from flican.core.artifacts import copy_artifact, file_digest
from flican.core.oci import inspect_oci, materialize_layout


class TestOCI(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.path = self.root / "image.oci.tar"

    def test_verified_layout_has_archive_manifest_config_and_layer_identities(self):
        expected = make_oci(self.path)
        value = inspect_oci(self.path)
        self.assertEqual(value["manifest_digest"], expected["manifest_digest"])
        self.assertEqual(value["config_digest"], expected["config_digest"])
        self.assertEqual(value["archive_sha256"], file_digest(self.path))
        self.assertEqual(value["resolved_uid"], 65532)
        layout = materialize_layout(self.path, self.root / "layout", value)
        self.assertTrue((layout / "index.json").is_file())
        self.assertFalse((layout / "hello.txt").exists())  # Filesystem layers are never extracted on the host.

    def test_empty_and_numeric_root_user_are_detected_from_effective_config(self):
        for user in ("", "0", "00:1000"):
            with self.subTest(user=user):
                make_oci(self.path, user=user)
                self.assertEqual(inspect_oci(self.path)["user_status"], "root")

    def test_named_user_resolution_obeys_layer_updates_and_whiteouts(self):
        base = {"etc/passwd": b"root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000:app:/app:/bin/sh\n"}
        cases = (([base], 1000), ([base, {"etc/passwd": b"app:x:0:0:root:/root:/bin/sh\n"}], 0),
                 ([base, {"etc/.wh.passwd": b""}], None), ([base, {"etc/.wh..wh..opq": b""}], None),
                 ([base, {".wh..wh..opq": b""}], None),
                 ([base, {"etc/.wh.passwd": b"", "etc/passwd": b"app:x:2000:2000:a:/app:/bin/sh\n"}], 2000))
        for layers, uid in cases:
            with self.subTest(uid=uid, layers=len(layers)):
                make_oci(self.path, user="app", layers=layers)
                self.assertEqual(inspect_oci(self.path)["resolved_uid"], uid)

    def test_ambiguous_and_linked_passwd_never_claim_nonroot(self):
        for files in ({"etc/passwd": b"app:x:1000:1000:a:/a:/bin/sh\napp:x:0:0:r:/r:/bin/sh\n"},
                      {"etc/passwd": (tarfile.SYMTYPE, "/other/passwd")},
                      {"etc": (tarfile.SYMTYPE, "/other"), "etc/passwd": b"app:x:1000:1000:a:/a:/bin/sh\n"}):
            make_oci(self.path, user="app", files=files)
            self.assertEqual(inspect_oci(self.path)["user_status"], "unresolved")

    def test_whiteout_never_masks_a_same_layer_etc_symlink_regardless_of_order(self):
        entries = [("etc", (tarfile.SYMTYPE, "/other")), (".wh.etc", b""),
                   ("etc/passwd", b"app:x:1000:1000:a:/app:/bin/sh\n")]
        for items in (entries, list(reversed(entries))):
            make_oci(self.path, user="app", layers=[dict(items)])
            self.assertEqual(inspect_oci(self.path)["user_status"], "unresolved")

    def test_whiteout_replacing_an_old_etc_symlink_can_resolve_the_new_user(self):
        make_oci(self.path, user="app", layers=[{"etc": (tarfile.SYMTYPE, "/old")},
                 {".wh.etc": b"", "etc/passwd": b"app:x:1000:1000:a:/app:/bin/sh\n"}])
        self.assertEqual(inspect_oci(self.path)["resolved_uid"], 1000)

    def test_changed_blob_or_descriptor_is_rejected(self):
        def alter(members):
            name = next(key for key in members if key.startswith("blobs/"))
            members[name] = b"x" * len(members[name])
        make_oci(self.path, mutate=alter)
        with self.assertRaisesRegex(ValueError, "digest"):
            inspect_oci(self.path)

    def test_index_platform_must_agree_with_configuration(self):
        def alter(members):
            index = json.loads(members["index.json"])
            index["manifests"][0]["platform"] = {"os": "linux", "architecture": "arm64"}
            members["index.json"] = json.dumps(index).encode()
        make_oci(self.path, mutate=alter)
        with self.assertRaisesRegex(ValueError, "platform does not match"):
            inspect_oci(self.path)

    def test_rehashed_graph_cannot_hide_an_incorrect_uncompressed_layer_digest(self):
        def alter(members):
            index = json.loads(members["index.json"])
            manifest = json.loads(members["blobs/sha256/" + index["manifests"][0]["digest"][7:]])
            config = json.loads(members["blobs/sha256/" + manifest["config"]["digest"][7:]])
            config["rootfs"]["diff_ids"][0] = "sha256:" + "0" * 64
            for value, descriptor in ((config, manifest["config"]), (manifest, index["manifests"][0])):
                data = json.dumps(value).encode()
                digest = hashlib.sha256(data).hexdigest()
                members["blobs/sha256/" + digest] = data
                descriptor.update(digest="sha256:" + digest, size=len(data))
            members["index.json"] = json.dumps(index).encode()
        make_oci(self.path, mutate=alter)
        with self.assertRaisesRegex(ValueError, "uncompressed layer digest"):
            inspect_oci(self.path)

    def test_layout_traversal_and_links_are_rejected_without_writing_files(self):
        make_oci(self.path, mutate=lambda members: members.update({"../../outside": b"untrusted"}))
        with self.assertRaises(ValueError):
            inspect_oci(self.path)
        self.assertFalse((self.root.parent / "outside").exists())
        with tarfile.open(self.path, "w") as archive:
            member = tarfile.TarInfo("index.json")
            member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
            archive.addfile(member)
        with self.assertRaises(ValueError):
            inspect_oci(self.path)

    def test_multiple_platforms_and_duplicate_json_keys_are_rejected(self):
        def multiple(members):
            value = json.loads(members["index.json"])
            value["manifests"] *= 2
            members["index.json"] = json.dumps(value).encode()
        make_oci(self.path, mutate=multiple)
        with self.assertRaisesRegex(ValueError, "one image platform"):
            inspect_oci(self.path)
        make_oci(self.path, mutate=lambda m: m.update({"index.json": b'{"schemaVersion":2,"schemaVersion":2,"manifests":[]}'}))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            inspect_oci(self.path)

    def test_streaming_copy_supports_images_larger_than_report_limit(self):
        source, target = self.root / "large.oci.tar", self.root / "copy.oci.tar"
        with source.open("wb") as stream:
            stream.truncate(65 * 1024 * 1024)
        digest, size = copy_artifact(source, target, limit=70 * 1024 * 1024)
        self.assertEqual(size, 65 * 1024 * 1024)
        self.assertEqual(digest, file_digest(target, 70 * 1024 * 1024))
        with self.assertRaises(ValueError):
            file_digest(source)

    def test_external_symlink_input_is_rejected(self):
        make_oci(self.path)
        alias = self.root / "alias.tar"
        alias.symlink_to(self.path)
        with self.assertRaises(ValueError):
            inspect_oci(alias)
