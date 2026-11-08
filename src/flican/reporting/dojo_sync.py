"""Stable DefectDojo contexts, replayable reimport and verified receipts."""

import json
import re
from datetime import date, timedelta
from pathlib import Path

from flican.core.config import load_config
from flican.core.discovery import discover_files
from flican.core.provenance import canonical_digest, load_attested_run, scanner_profiles, utc_now
from flican.core.state import StateStore, read_private_json, state_directory, state_lock, write_private_json
from flican.reporting.dojo_client import DojoAPIError, DojoClient
from flican.reporting.dojo_export import SCANNERS, export_scanner, test_type_name


def connection_details() -> dict:
    path = state_directory() / "defectdojo/connection.json"
    if not path.is_file():
        raise ValueError("No local DefectDojo connection; run flican platform up first.")
    connection = read_private_json(path)
    if not isinstance(connection.get("url"), str) or not isinstance(connection.get("token"), str):
        raise ValueError("Invalid local DefectDojo connection file.")
    if type(connection.get("product_type_id")) is not int or not isinstance(connection.get("test_types"), dict):
        raise ValueError("Invalid local DefectDojo context configuration.")
    if any(type(connection["test_types"].get(name)) is not int for name in SCANNERS):
        raise ValueError("The local DefectDojo scanner types have not been bootstrapped.")
    return connection


def context_identity(project_path: Path, scope: str, url: str) -> tuple[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,79}", scope):
        raise ValueError("Scope must be a short branch/environment name without spaces.")
    project_key = canonical_digest({"path": str(project_path.resolve()), "url": url})
    return project_key, canonical_digest({"project": project_key, "scope": scope, "version": 1})


def _id(value) -> int | None:
    identifier = value.get("id") if isinstance(value, dict) else value
    return identifier if type(identifier) is int and identifier > 0 else None


def _matches(remote: dict, expected: dict) -> bool:
    for key, value in expected.items():
        observed = remote.get(key)
        if type(value) is int:
            observed = _id(observed)
        if observed != value:
            return False
    return True


def _ensure(client: DojoClient, resource: str, identifier: int | None,
            filters: dict, identity: dict, payload: dict) -> dict:
    if identifier is not None:
        result = client.request("GET", f"/api/v2/{resource}/{identifier}/")
        if not _matches(result, identity):
            raise ValueError("The registered DefectDojo context was changed or replaced.")
        return result
    matches = [item for item in client.list(resource, **filters) if _matches(item, identity)]
    if len(matches) > 1:
        raise ValueError("Ambiguous DefectDojo objects; no automatic adoption was performed.")
    result = matches[0] if matches else client.request("POST", f"/api/v2/{resource}/", payload)
    if not isinstance(result, dict) or _id(result) is None or not _matches(result, identity):
        raise DojoAPIError("DefectDojo returned an unexpected context-creation receipt.")
    return result


def _verify_test(client: DojoClient, context: dict, stream: dict, scanner: str) -> dict:
    remote = client.request("GET", f"/api/v2/tests/{stream['test_id']}/")
    expected = {"engagement": context["engagement_id"], "title": stream["title"],
                "test_type_name": test_type_name(scanner)}
    if not _matches(remote, expected):
        raise ValueError("The registered Test no longer belongs to this scanner context.")
    if remote.get("deduplication_algorithm") != "unique_id_from_tool":
        raise ValueError("This Test must use the unique_id_from_tool deduplication algorithm.")
    if remote.get("hash_code_fields") != ["unique_id_from_tool"]:
        raise ValueError("This Test must hash unique_id_from_tool only.")
    return remote


def initialize_context(project_path: Path, scope: str = "local") -> dict:
    project_path = project_path.resolve(strict=True)
    config = load_config(project_path / "flican.yaml")
    excluded = set(config["project"]["exclude"]) | {".flican"}
    # Keep selection consistent with scan; only ignore-file content contributes to profiles.
    selected = discover_files(project_path, excluded)
    profiles = scanner_profiles(project_path, config["scanners"], excluded, paths=selected)
    connection = connection_details()
    project_key, key = context_identity(project_path, scope, connection["url"])
    client = DojoClient(connection["url"], connection["token"])
    with state_lock():
        store = StateStore()
        for scanner, profile in profiles.items():
            stream = store.get("stream", key + ":" + scanner)
            if stream and stream["profile_hash"] != profile["hash"]:
                raise ValueError("Scanner profile changed; initialize a new --scope for this profile.")
        project = store.get("project", project_key) or {
            "name": config["project"]["name"][:160] + " [" + project_key[:12] + "]",
            "prod_type": connection["product_type_id"],
        }
        product_identity = {"name": project["name"], "prod_type": project["prod_type"]}
        remote = _ensure(client, "products", project.get("id"), {"name": project["name"]},
                         product_identity, {**product_identity, "description": "Managed Flican project."})
        project["id"] = remote["id"]
        store.put("project", project_key, project)
        context = store.get("context", key) or {
            "key": key, "scope": scope, "project_path": str(project_path),
            "url": connection["url"], "product_id": project["id"],
            "product_name": project["name"], "prod_type": project["prod_type"],
            "engagement_name": f"Flican {scope} [{key[:12]}]",
        }
        engagement_identity = {"name": context["engagement_name"], "product": context["product_id"]}
        today = date.today()
        remote = _ensure(
            client, "engagements", context.get("engagement_id"), {"product": project["id"]},
            engagement_identity, {**engagement_identity, "target_start": today.isoformat(),
                                  "target_end": (today + timedelta(days=365)).isoformat(),
                                  "engagement_type": "CI/CD", "status": "In Progress"},
        )
        context["engagement_id"] = remote["id"]
        store.put("context", key, context)
        for scanner, profile in profiles.items():
            stream_key = key + ":" + scanner
            stream = store.get("stream", stream_key) or {
                "profile_hash": profile["hash"],
                "title": f"Flican {scanner} [{profile['hash'][:12]}]",
            }
            identity = {"title": stream["title"], "engagement": context["engagement_id"],
                        "test_type": connection["test_types"][scanner]}
            remote = _ensure(
                client, "tests", stream.get("test_id"), {"engagement": context["engagement_id"]},
                identity, {**identity, "scan_type": "Generic Findings Import", "target_start": utc_now(),
                           "target_end": utc_now(), "environment": None,
                           "description": f"Flican {scanner}; profile {profile['hash']}"},
            )
            stream["test_id"] = remote["id"]
            store.put("stream", stream_key, stream)
            _verify_test(client, context, stream, scanner)
        return context


def _write_receipt(store: StateStore, run_path: Path, key: str, receipt: dict) -> None:
    store.put("receipt", key, receipt)
    filename = f"defectdojo-{receipt['context'][:12]}-{receipt['scanner']}-{int(receipt['close_old'])}.json"
    write_private_json(run_path / "reporting" / filename, receipt)


def sync_run(run_path: Path, scope: str = "local", scanner: str | None = None,
             close_old: bool = False) -> list[dict]:
    connection = connection_details()
    with state_lock():
        store = StateStore()
        manifest, report = load_attested_run(run_path, store)
        _, key = context_identity(Path(manifest["project_path"]), scope, connection["url"])
        context = store.get("context", key)
        if context is None:
            raise ValueError("No context for this project/scope; run flican dojo init first.")
        selected = [scanner] if scanner else [name for name in SCANNERS if name in manifest["profiles"]]
        if any(name not in manifest["profiles"] for name in selected):
            raise ValueError("The requested scanner is not part of this run.")
        operations = []
        # Validate all selections before allowing any upload or closure.
        for name in selected:
            stream = store.get("stream", key + ":" + name)
            if not stream or stream["profile_hash"] != manifest["profiles"][name]["hash"]:
                raise ValueError("No compatible registered scanner profile; initialize a new --scope.")
            latest = stream.get("latest_started_at")
            if latest and (manifest["started_at"] < latest or (
                manifest["started_at"] == latest and stream.get("latest_run_id") != manifest["run_id"]
            )):
                raise ValueError("An older run cannot overwrite a newer scan in this Test.")
            if close_old and not manifest["completion"][name]["can_close_old"]:
                raise ValueError("Closing old findings requires attested complete coverage; select an eligible scanner.")
            exported = export_scanner(report["findings"], name, key, stream["profile_hash"], manifest["completed_at"])
            gate = report.get("gate", {})
            verdict = "PASS" if gate.get("passed") is True else "FAIL"
            details = report.get("coverage", {}).get(name, {"status": "not_attested"})
            exported["description"] = (
                f"Flican run: {manifest['run_id']}\n"
                f"Started: {manifest['started_at']}\nCompleted: {manifest['completed_at']}\n"
                f"Local policy gate: {verdict} (threshold {gate.get('fail_on')})\n"
                f"Scanner profile: {stream['profile_hash']}\n"
                f"Coverage: {json.dumps(details, sort_keys=True)}\n"
                f"Automatic closure requested: {close_old}"
            )
            receipt_key = canonical_digest([key, manifest["run_id"], name, close_old])
            receipt = store.get("receipt", receipt_key)
            payload_hash = canonical_digest(exported)
            if receipt and receipt["payload_sha256"] != payload_hash:
                raise ValueError("This sync receipt refers to a different report payload.")
            if not receipt:
                receipt = {"run_id": manifest["run_id"], "context": key, "scanner": name,
                           "test_id": stream["test_id"], "close_old": close_old,
                           "payload_sha256": payload_hash, "finding_count": len(exported["findings"]),
                           "status": "pending"}
            operations.append((name, stream, exported, receipt_key, receipt))
        client = DojoClient(connection["url"], connection["token"])
        outcomes = []
        for name, stream, exported, receipt_key, receipt in operations:
            if receipt["status"] == "synced":
                outcomes.append({**receipt, "status": "already_synced"})
                continue
            stream.update(latest_started_at=manifest["started_at"], latest_run_id=manifest["run_id"])
            store.put("stream", key + ":" + name, stream)
            receipt.update(status="pending", attempted_at=utc_now())
            _write_receipt(store, run_path, receipt_key, receipt)
            export_name = f"generic-{key[:12]}-{name}-{int(close_old)}.json"
            write_private_json(run_path / "reporting" / export_name, exported)
            try:
                product = client.request("GET", f"/api/v2/products/{context['product_id']}/")
                engagement = client.request("GET", f"/api/v2/engagements/{context['engagement_id']}/")
                if not _matches(product, {"name": context["product_name"], "prod_type": context["prod_type"]}) or not _matches(
                    engagement, {"name": context["engagement_name"], "product": context["product_id"]},
                ):
                    raise ValueError("The registered DefectDojo parent context was changed or replaced.")
                _verify_test(client, context, stream, name)
                result = client.reimport(stream["test_id"], exported, close_old=close_old,
                                         completed_at=manifest["completed_at"])
                if _id(result.get("test_id", result.get("test"))) != stream["test_id"]:
                    raise DojoAPIError("DefectDojo reimport returned a different Test ID.")
                remote = client.list("findings", test=stream["test_id"])
                if any(_id(item.get("test")) != stream["test_id"] for item in remote):
                    raise DojoAPIError("DefectDojo finding readback escaped its Test scope.")
                incoming = {item["unique_id_from_tool"] for item in exported["findings"]}
                for identity in incoming:
                    if sum(item.get("unique_id_from_tool") == identity for item in remote) != 1:
                        raise DojoAPIError("DefectDojo finding identities could not be verified uniquely.")
                updated_test = client.request("GET", f"/api/v2/tests/{stream['test_id']}/")
                if updated_test.get("description") != exported["description"]:
                    raise DojoAPIError("DefectDojo did not confirm the imported run metadata.")
                if close_old and any(item.get("active") and item.get("unique_id_from_tool") not in incoming
                                     for item in remote):
                    raise DojoAPIError("DefectDojo did not confirm closure of the missing findings.")
                receipt.update(status="synced", verified_at=utc_now())
                receipt.pop("last_error", None)
                _write_receipt(store, run_path, receipt_key, receipt)
                outcomes.append(receipt)
            except (OSError, ValueError, RuntimeError) as error:
                receipt.update(status="pending", last_error=str(error))
                _write_receipt(store, run_path, receipt_key, receipt)
                raise
        return outcomes
