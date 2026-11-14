"""Zero-Disk-Footprint KeePassXC reader via direct in-memory KDBX or CLI pipe."""

import base64
import gc
import subprocess
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Sequence

from .models import TOTPEntry
from .security import scrub_bytes


class KeePassXCError(Exception):
    """Base exception for KeePass reading, CLI invocation, or parsing failures."""
    pass


class KeePassCredentialsError(KeePassXCError):
    """Raised when master password, keyfile, or credentials are invalid."""
    pass


class KeePassCorruptedError(KeePassXCError):
    """Raised when KDBX header, payload, or file structure is corrupted."""
    pass


def clean_base32(raw: Optional[str]) -> Optional[str]:
    """Cleans spaces, hyphens, validates, and normalizes a Base32 secret string.

    Returns normalized uppercase Base32 string, or None if invalid.
    """
    if not raw or not isinstance(raw, str):
        return None
    cleaned = raw.replace(" ", "").replace("-", "").strip().upper().rstrip("=")
    if not cleaned:
        return None
    missing_padding = len(cleaned) % 8
    padded = cleaned + ("=" * ((8 - missing_padding) % 8)) if missing_padding != 0 else cleaned
    try:
        base64.b32decode(padded)
        return cleaned
    except Exception:
        return None


def normalize_algorithm(algo_raw: Optional[str]) -> str:
    """Normalizes HMAC algorithm names (e.g. HMAC-SHA-1 -> SHA1, HMAC-SHA-256 -> SHA256).

    Defaults to 'SHA1' in compliance with RFC 6238.
    """
    if not algo_raw or not isinstance(algo_raw, str):
        return "SHA1"
    clean = algo_raw.strip().upper().replace("-", "").replace("_", "")
    if clean.startswith("HMAC"):
        clean = clean[4:]
    if clean in ("SHA1", "SHA256", "SHA512"):
        return clean
    return "SHA1"


def parse_totp_settings(settings_str: Optional[str]) -> tuple[int, int, str]:
    """Parses KeeTrayTOTP 'TOTP Settings' field (e.g. '30;6', '60;8;SHA256', '30:6')."""
    period = 30
    digits = 6
    algo = "SHA1"
    if not settings_str or not isinstance(settings_str, str):
        return period, digits, algo
    sep = ";" if ";" in settings_str else (":" if ":" in settings_str else None)
    parts = [p.strip() for p in settings_str.split(sep)] if sep else [settings_str.strip()]
    if len(parts) >= 1 and parts[0].isdigit():
        period = int(parts[0])
    if len(parts) >= 2 and parts[1].isdigit():
        digits = int(parts[1])
    if len(parts) >= 3:
        algo = normalize_algorithm(parts[2])
    return period, digits, algo


def parse_otpauth_uri(
    uri: str,
    fallback_title: str = "",
    fallback_user: str = "",
) -> Optional[TOTPEntry]:
    """Parses an otpauth://totp/... URI into a TOTPEntry.

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
        clean_sec = clean_base32(secrets[0])
        if not clean_sec:
            return None

        # Issuer precedence: query param > path issuer > fallback_title > path_account > fallback_user
        query_issuers = qs.get("issuer", [])
        if query_issuers and query_issuers[0].strip():
            issuer = query_issuers[0].strip()
        elif path_issuer.strip():
            issuer = path_issuer.strip()
        elif fallback_title.strip():
            issuer = fallback_title.strip()
        elif path_account.strip():
            issuer = path_account.strip()
        elif fallback_user.strip():
            issuer = fallback_user.strip()
        else:
            issuer = "Unknown"

        # Account precedence: path_account > fallback_user > fallback_title
        if path_account.strip():
            account = path_account.strip()
        elif fallback_user.strip():
            account = fallback_user.strip()
        elif fallback_title.strip():
            account = fallback_title.strip()
        else:
            account = "Unknown"

        # Algorithm
        algorithm = normalize_algorithm(qs.get("algorithm", ["SHA1"])[0])

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
            secret=clean_sec,
            algorithm=algorithm,
            digits=digits,
            period=period,
        )
    except Exception:
        return None


def extract_totp_from_entry(entry) -> Optional[TOTPEntry]:
    """Extracts TOTPEntry from a pykeepass.entry.Entry supporting all known schemas."""
    title = (getattr(entry, "title", None) or "").strip()
    username = (getattr(entry, "username", None) or "").strip()

    # 1. Standard entry.otp field
    entry_otp = getattr(entry, "otp", None)
    if entry_otp and isinstance(entry_otp, str):
        otp_str = entry_otp.strip()
        if otp_str.lower().startswith("otpauth://totp/"):
            res = parse_otpauth_uri(otp_str, fallback_title=title, fallback_user=username)
            if res:
                return res
        elif otp_str.lower().startswith("otpauth://hotp/"):
            return None
        elif "key=" in otp_str:
            qs = urllib.parse.parse_qs(otp_str)
            sec = clean_base32(qs.get("key", [""])[0])
            if sec:
                try:
                    p = int(qs.get("step", ["30"])[0])
                except (ValueError, TypeError):
                    p = 30
                try:
                    d = int(qs.get("size", ["6"])[0])
                except (ValueError, TypeError):
                    d = 6
                algo = normalize_algorithm(qs.get("enc", ["SHA1"])[0])
                return TOTPEntry(
                    issuer=title or username or "Unknown",
                    account=username or title or "Unknown",
                    secret=sec,
                    algorithm=algo,
                    digits=d,
                    period=p,
                )

    # 2. Inspect entry.custom_properties with case-insensitive normalization
    custom_props = getattr(entry, "custom_properties", None)
    if custom_props and isinstance(custom_props, dict):
        norm_props = {
            str(k).strip().lower(): str(v).strip()
            for k, v in custom_props.items()
            if k is not None and v is not None
        }

        # Case where OTP was stored in custom property 'OTP' or 'otp'
        if "otp" in norm_props:
            custom_otp = norm_props["otp"]
            if custom_otp.lower().startswith("otpauth://totp/"):
                res = parse_otpauth_uri(custom_otp, fallback_title=title, fallback_user=username)
                if res:
                    return res
            elif custom_otp.lower().startswith("otpauth://hotp/"):
                return None
            elif "key=" in custom_otp:
                qs = urllib.parse.parse_qs(custom_otp)
                sec = clean_base32(qs.get("key", [""])[0])
                if sec:
                    try:
                        p = int(qs.get("step", ["30"])[0])
                    except (ValueError, TypeError):
                        p = 30
                    try:
                        d = int(qs.get("size", ["6"])[0])
                    except (ValueError, TypeError):
                        d = 6
                    algo = normalize_algorithm(qs.get("enc", ["SHA1"])[0])
                    return TOTPEntry(
                        issuer=title or username or "Unknown",
                        account=username or title or "Unknown",
                        secret=sec,
                        algorithm=algo,
                        digits=d,
                        period=p,
                    )

        # Native KeePass 2.47+ / KeeTrayTOTP properties
        raw_sec = (
            norm_props.get("timeotp-secret-base32")
            or norm_props.get("totp seed")
            or norm_props.get("timeotp-secret")
            or norm_props.get("otp-secret")
            or norm_props.get("totp-secret")
        )
        if raw_sec:
            clean_sec = clean_base32(raw_sec)
            if clean_sec:
                sett_period, sett_digits, sett_algo = parse_totp_settings(norm_props.get("totp settings", ""))
                raw_period = (
                    norm_props.get("timeotp-period")
                    or norm_props.get("otp-period")
                    or norm_props.get("totp-period")
                )
                if raw_period:
                    try:
                        period = int(raw_period)
                    except (ValueError, TypeError):
                        period = sett_period
                else:
                    period = sett_period

                raw_digits = (
                    norm_props.get("timeotp-length")
                    or norm_props.get("timeotp-digits")
                    or norm_props.get("otp-length")
                    or norm_props.get("totp-digits")
                )
                if raw_digits:
                    try:
                        digits = int(raw_digits)
                    except (ValueError, TypeError):
                        digits = sett_digits
                else:
                    digits = sett_digits

                raw_algo = (
                    norm_props.get("timeotp-algorithm")
                    or norm_props.get("otp-algorithm")
                    or norm_props.get("totp-algorithm")
                )
                if raw_algo:
                    algorithm = normalize_algorithm(raw_algo)
                else:
                    algorithm = sett_algo

                issuer = title or username or "Unknown"
                account = username or title or "Unknown"

                return TOTPEntry(
                    issuer=issuer,
                    account=account,
                    secret=clean_sec,
                    algorithm=algorithm,
                    digits=digits,
                    period=period,
                )

    return None


def is_entry_excluded(
    entry,
    normalized_excluded: set[str],
    recycle_bin_uuid: Optional[object] = None,
    recycle_bin_name: Optional[str] = None,
) -> bool:
    """Checks whether an entry is inside an excluded group or the Recycle Bin."""
    # 1. Ancestor group traversal
    grp = getattr(entry, "parentgroup", None)
    while grp is not None and not getattr(grp, "is_root_group", False):
        if recycle_bin_uuid and getattr(grp, "uuid", None) == recycle_bin_uuid:
            return True
        grp_name = getattr(grp, "name", None)
        if grp_name:
            gname_clean = grp_name.strip().lower()
            if gname_clean in normalized_excluded:
                return True
            if recycle_bin_name and gname_clean == recycle_bin_name:
                return True
        grp = getattr(grp, "parentgroup", None)

    # 2. Path verification (guarding entry.path is not None)
    entry_path = getattr(entry, "path", None)
    if entry_path and isinstance(entry_path, list) and len(entry_path) > 1:
        for gname in entry_path[:-1]:
            if gname:
                gclean = str(gname).strip().lower()
                if gclean in normalized_excluded:
                    return True
                if recycle_bin_name and gclean == recycle_bin_name:
                    return True

    return False


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
        entry_title = ""
        entry_user = ""
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
                if key_text:
                    key_lower = key_text.lower()
                    if key_lower == "title" and value_text:
                        entry_title = value_text.strip()
                    elif key_lower == "username" and value_text:
                        entry_user = value_text.strip()
                    elif key_lower == "otp" and value_text:
                        otp_uri = value_text.strip()

        if otp_uri and otp_uri.startswith("otpauth://"):
            parsed_entry = parse_otpauth_uri(
                otp_uri,
                fallback_title=entry_title,
                fallback_user=entry_user,
            )
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


def read_kdbx_direct(
    db_path: str | Path,
    password: str | bytes | bytearray | None = None,
    keyfile_path: str | Path | None = None,
    excluded_groups: Sequence[str] = ("Recycle Bin", "Archive"),
) -> list[TOTPEntry]:
    """Reads a KDBX database directly in memory via pykeepass and extracts TOTP entries.

    Zero subprocesses, zero disk writes, complete credential scrubbing.
    """
    path_obj = Path(db_path)
    if not path_obj.exists():
        raise KeePassXCError(f"KeePassXC database not found: {db_path}")

    keyfile_str: Optional[str] = None
    if keyfile_path:
        kf_obj = Path(keyfile_path)
        if not kf_obj.exists():
            raise KeePassXCError(f"Keyfile not found: {keyfile_path}")
        keyfile_str = str(keyfile_path)

    # Convert password safely to str for pykeepass, track mutable buffer for zeroing
    pw_buf: Optional[bytearray] = None
    password_str: Optional[str] = None
    if password is not None:
        if isinstance(password, (bytes, bytearray)):
            pw_buf = bytearray(password)
            password_str = password.decode("utf-8", errors="replace")
        else:
            password_str = str(password)
            pw_buf = bytearray(password_str.encode("utf-8"))

    kp = None
    try:
        try:
            from pykeepass import PyKeePass
            import pykeepass.exceptions as pke
        except ImportError as err:
            raise KeePassXCError(f"pykeepass library is not installed: {err}") from err

        try:
            kp = PyKeePass(
                str(path_obj),
                password=password_str,
                keyfile=keyfile_str,
            )
        except pke.CredentialsError as err:
            raise KeePassCredentialsError(f"Invalid master credentials for {db_path}: {err}") from err
        except (pke.HeaderChecksumError, pke.PayloadChecksumError, pke.BinaryError) as err:
            raise KeePassCorruptedError(f"Corrupt or invalid KeePass database: {err}") from err
        except Exception as err:
            err_name = type(err).__name__
            if (
                "StreamError" in err_name
                or "ConstructError" in err_name
                or "CheckError" in err_name
                or "ChecksumError" in err_name
            ):
                raise KeePassCorruptedError(f"Failed to parse KeePass database structure: {err}") from err
            raise KeePassXCError(f"Failed to open KeePass database: {err}") from err

        # Safe recycle bin detection (handling missing RecycleBinUUID tag bug in pykeepass)
        recycle_bin_uuid = None
        recycle_bin_name = None
        try:
            rb = kp.recyclebin_group
            if rb is not None:
                recycle_bin_uuid = getattr(rb, "uuid", None)
                rb_name = getattr(rb, "name", None)
                recycle_bin_name = rb_name.strip().lower() if rb_name else None
        except Exception:
            pass

        norm_excluded = {g.strip().lower() for g in excluded_groups if g}
        if recycle_bin_name:
            norm_excluded.add(recycle_bin_name)

        totp_entries: list[TOTPEntry] = []
        try:
            for entry in kp.entries:
                if is_entry_excluded(entry, norm_excluded, recycle_bin_uuid, recycle_bin_name):
                    continue
                parsed = extract_totp_from_entry(entry)
                if parsed is not None:
                    totp_entries.append(parsed)
        except (AttributeError, Exception) as err:
            raise KeePassCorruptedError(f"Corrupted KeePass database structure or payload: {err}") from err

        return totp_entries

    finally:
        # Scrub in-memory credentials and XML DOM
        password_str = None
        if pw_buf is not None:
            scrub_bytes(pw_buf)
        if kp is not None:
            try:
                kp._password = None
                kp._keyfile = None
                if hasattr(kp, "kdbx") and kp.kdbx is not None:
                    if hasattr(kp.kdbx, "body") and kp.kdbx.body is not None:
                        if hasattr(kp.kdbx.body, "transformed_key"):
                            kp.kdbx.body.transformed_key = None
                        if hasattr(kp.kdbx.body, "master_key"):
                            kp.kdbx.body.master_key = None
                        if hasattr(kp.kdbx.body, "payload"):
                            kp.kdbx.body.payload = None
                        kp.kdbx.body = None
                    del kp.kdbx
                if hasattr(kp, "_xml"):
                    del kp._xml
            except Exception:
                pass
            del kp
        gc.collect()


def read_kpxc_entries_cli(
    db_path: str | Path,
    password: str | bytes | bytearray | None = None,
    keyfile_path: str | Path | None = None,
    yubikey_slot: str | int | None = None,
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

    if yubikey_slot is not None and str(yubikey_slot).strip():
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


def read_kpxc_entries(
    db_path: str | Path,
    password: str | bytes | bytearray | None = None,
    keyfile_path: str | Path | None = None,
    yubikey_slot: str | int | None = None,
    cli_binary: str = "keepassxc-cli",
    excluded_groups: Sequence[str] = ("Recycle Bin", "Archive"),
    backend: str = "auto",
) -> list[TOTPEntry]:
    """Facade for KeePass reading supporting direct pykeepass, CLI, and auto dispatch."""
    norm_backend = backend.strip().lower()

    # Check if yubikey_slot is active
    has_yubikey = yubikey_slot is not None and str(yubikey_slot).strip() != ""

    if norm_backend == "cli":
        return read_kpxc_entries_cli(
            db_path=db_path,
            password=password,
            keyfile_path=keyfile_path,
            yubikey_slot=yubikey_slot,
            cli_binary=cli_binary,
            excluded_groups=excluded_groups,
        )

    if norm_backend == "direct":
        if has_yubikey:
            raise KeePassXCError(
                "Direct pykeepass backend does not support YubiKey challenge-response. Use backend='cli'."
            )
        return read_kdbx_direct(
            db_path=db_path,
            password=password,
            keyfile_path=keyfile_path,
            excluded_groups=excluded_groups,
        )

    if norm_backend == "auto":
        if has_yubikey:
            return read_kpxc_entries_cli(
                db_path=db_path,
                password=password,
                keyfile_path=keyfile_path,
                yubikey_slot=yubikey_slot,
                cli_binary=cli_binary,
                excluded_groups=excluded_groups,
            )
        return read_kdbx_direct(
            db_path=db_path,
            password=password,
            keyfile_path=keyfile_path,
            excluded_groups=excluded_groups,
        )

    raise ValueError(f"Invalid backend: '{backend}'. Expected 'auto', 'direct', or 'cli'.")
