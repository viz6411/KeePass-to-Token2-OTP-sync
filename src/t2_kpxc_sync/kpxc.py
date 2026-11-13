"""Zero-Disk-Footprint KeePassXC reader via keepassxc-cli pipe."""

import subprocess
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Sequence

from .models import TOTPEntry
from .security import scrub_bytes


class KeePassXCError(Exception):
    """Raised when keepassxc-cli invocation or parsing fails."""
    pass


def parse_otpauth_uri(uri: str) -> Optional[TOTPEntry]:
    """Parses an otpauth:// TOTP URI into a TOTPEntry.

    Returns None if URI is invalid, not TOTP, or missing secret.
    """
    if not uri or not isinstance(uri, str):
        return None

    try:
        parsed = urllib.parse.urlparse(uri.strip())
        if parsed.scheme.lower() != "otpauth":
            return None
        if parsed.netloc.lower() != "totp":
            return None

        # Path: [/]Issuer:Account or [/]Account
        raw_path = urllib.parse.unquote(parsed.path.lstrip("/"))
        if ":" in raw_path:
            path_issuer, path_account = raw_path.split(":", 1)
        else:
            path_issuer = ""
            path_account = raw_path

        qs = urllib.parse.parse_qs(parsed.query)

        # Secret is mandatory
        secrets = qs.get("secret", [])
        if not secrets or not secrets[0].strip():
            return None
        secret = secrets[0].replace(" ", "").upper()

        # Issuer: query param overrides path
        query_issuers = qs.get("issuer", [])
        if query_issuers and query_issuers[0].strip():
            issuer = query_issuers[0].strip()
        elif path_issuer.strip():
            issuer = path_issuer.strip()
        else:
            issuer = path_account.strip()

        account = path_account.strip()

        # Algorithm
        algorithm = qs.get("algorithm", ["SHA1"])[0].strip().upper()

        # Digits
        digits_raw = qs.get("digits", ["6"])[0]
        try:
            digits = int(digits_raw)
        except ValueError:
            digits = 6

        # Period
        period_raw = qs.get("period", ["30"])[0]
        try:
            period = int(period_raw)
        except ValueError:
            period = 30

        return TOTPEntry(
            issuer=issuer,
            account=account,
            secret=secret,
            algorithm=algorithm,
            digits=digits,
            period=period,
        )
    except Exception:
        return None


def _clean_tag(tag: str) -> str:
    """Strips XML namespace from tag name."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse_kpxc_xml(
    xml_content: str | bytes,
    excluded_groups: Sequence[str] = ("Recycle Bin", "Archive"),
) -> list[TOTPEntry]:
    """Parses KeePass 2.x XML export in memory and extracts TOTPEntry objects.

    Excludes groups matching excluded_groups (case-insensitive) and history entries.
    Zero disk files created.
    """
    if isinstance(xml_content, str):
        xml_content = xml_content.encode("utf-8")

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as err:
        raise KeePassXCError(f"Failed to parse KeePass XML: {err}") from err

    normalized_excluded = {g.strip().lower() for g in excluded_groups}
    entries: list[TOTPEntry] = []

    # Check for RecycleBinUUID in Meta
    recycle_bin_uuid: Optional[str] = None
    for meta in root.iter():
        if _clean_tag(meta.tag) == "Meta":
            for child in meta:
                if _clean_tag(child.tag) == "RecycleBinUUID" and child.text:
                    recycle_bin_uuid = child.text.strip()
            break

    def process_group(group_elem: ET.Element, is_parent_excluded: bool = False) -> None:
        group_name = ""
        group_uuid = ""
        child_groups: list[ET.Element] = []
        child_entries: list[ET.Element] = []

        for child in group_elem:
            tag = _clean_tag(child.tag)
            if tag == "Name" and child.text:
                group_name = child.text.strip()
            elif tag == "UUID" and child.text:
                group_uuid = child.text.strip()
            elif tag == "Group":
                child_groups.append(child)
            elif tag == "Entry":
                child_entries.append(child)

        is_excluded = (
            is_parent_excluded
            or (group_name.lower() in normalized_excluded)
            or (bool(recycle_bin_uuid and group_uuid and group_uuid == recycle_bin_uuid))
        )

        if not is_excluded:
            for entry_elem in child_entries:
                process_entry(entry_elem)

        for sub_group in child_groups:
            process_group(sub_group, is_parent_excluded=is_excluded)

    def process_entry(entry_elem: ET.Element) -> None:
        otp_uri: Optional[str] = None
        for child in entry_elem:
            tag = _clean_tag(child.tag)
            # Skip history entries
            if tag == "History":
                continue
            if tag == "String":
                key_text: Optional[str] = None
                value_text: Optional[str] = None
                for str_child in child:
                    str_tag = _clean_tag(str_child.tag)
                    if str_tag == "Key":
                        key_text = (str_child.text or "").strip()
                    elif str_tag == "Value":
                        value_text = str_child.text or ""
                if key_text and key_text.lower() == "otp" and value_text:
                    otp_uri = value_text.strip()

        if otp_uri and otp_uri.startswith("otpauth://"):
            parsed_entry = parse_otpauth_uri(otp_uri)
            if parsed_entry:
                entries.append(parsed_entry)

    # Locate root Group(s)
    for elem in root:
        if _clean_tag(elem.tag) == "Root":
            for sub in elem:
                if _clean_tag(sub.tag) == "Group":
                    process_group(sub)
        elif _clean_tag(elem.tag) == "Group":
            process_group(elem)

    return entries


def read_kpxc_entries(
    db_path: str | Path,
    password: str | bytes | bytearray | None = None,
    keyfile_path: str | Path | None = None,
    yubikey_slot: str | None = None,
    cli_binary: str = "keepassxc-cli",
    excluded_groups: Sequence[str] = ("Recycle Bin", "Archive"),
) -> list[TOTPEntry]:
    """Streams KeePassXC database via keepassxc-cli export into RAM and parses entries.

    Zero disk writes: database is read strictly in Read-Only mode via pipe into RAM.
    """
    path_obj = Path(db_path)
    if not path_obj.exists():
        raise KeePassXCError(f"KeePassXC database not found: {db_path}")

    cmd = [cli_binary, "export"]
    if keyfile_path:
        keyfile_obj = Path(keyfile_path)
        if not keyfile_obj.exists():
            raise KeePassXCError(f"Keyfile not found: {keyfile_path}")
        cmd.extend(["--key-file", str(keyfile_path)])

    if yubikey_slot:
        cmd.extend(["--yubikey", str(yubikey_slot)])

    cmd.append(str(db_path))

    # Prepare password in bytearray for safe memory cleanup
    stdin_buf: bytearray | None = None
    try:
        if password is not None:
            if isinstance(password, bytearray):
                stdin_buf = bytearray(password) + b"\n"
            elif isinstance(password, bytes):
                stdin_buf = bytearray(password) + b"\n"
            else:
                stdin_buf = bytearray(str(password).encode("utf-8")) + b"\n"
        else:
            stdin_buf = bytearray(b"\n")

        try:
            proc = subprocess.run(
                cmd,
                input=bytes(stdin_buf),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except FileNotFoundError as err:
            raise KeePassXCError(f"keepassxc-cli binary not found: '{cli_binary}'") from err
        except Exception as err:
            raise KeePassXCError(f"Error running keepassxc-cli: {err}") from err

        if proc.returncode != 0:
            stderr_msg = proc.stderr.decode("utf-8", errors="replace").strip()
            raise KeePassXCError(
                f"keepassxc-cli export failed with exit code {proc.returncode}: {stderr_msg}"
            )

        return parse_kpxc_xml(proc.stdout, excluded_groups=excluded_groups)
    finally:
        if stdin_buf is not None:
            scrub_bytes(stdin_buf)
