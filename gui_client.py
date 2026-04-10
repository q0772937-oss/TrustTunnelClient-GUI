import base64
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import sys
import shlex
import tempfile
import threading
import subprocess


DEEP_LINK_PREFIX = "tt://?"


def _bootstrap_tcl_tk_env():
    if os.name != "nt":
        return

    existing_tcl = os.environ.get("TCL_LIBRARY")
    existing_tk = os.environ.get("TK_LIBRARY")
    if existing_tcl and existing_tk and os.path.isdir(existing_tcl) and os.path.isdir(existing_tk):
        return
    os.environ.pop("TCL_LIBRARY", None)
    os.environ.pop("TK_LIBRARY", None)

    candidates = [
        os.path.join(sys.base_prefix, "tcl"),
        os.path.join(sys.prefix, "tcl"),
        os.path.join(os.path.dirname(sys.executable), "tcl"),
    ]
    for tcl_root in candidates:
        tcl_lib = os.path.join(tcl_root, "tcl8.6")
        tk_lib = os.path.join(tcl_root, "tk8.6")
        if os.path.isdir(tcl_lib) and os.path.isdir(tk_lib):
            os.environ.setdefault("TCL_LIBRARY", tcl_lib)
            os.environ.setdefault("TK_LIBRARY", tk_lib)
            return


_bootstrap_tcl_tk_env()

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import traceback

import toml  # only for loading
import pystray
from PIL import Image, ImageDraw


# -----------------------------
# Helpers
# -----------------------------
def get_app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_bundle_dir() -> str:
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def get_user_data_dir() -> str:
    root = os.environ.get("LocalAppData") or get_app_dir()
    path = os.path.join(root, "TrustTunnelVPN")
    os.makedirs(path, exist_ok=True)
    return path


def tray_log_error(prefix: str):
    try:
        log_path = os.path.join(get_user_data_dir(), "tray_error.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\n--- {prefix} ---\n")
            f.write(traceback.format_exc())
    except Exception:
        pass


# -----------------------------
# TOML writer (no trailing commas in arrays)
# -----------------------------
def _toml_escape_string(s: str) -> str:
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def _toml_format_scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if v is None:
        return None
    return _toml_escape_string(str(v))


def _toml_format_array(arr: list) -> str:
    parts = []
    for item in arr:
        fv = _toml_format_scalar(item)
        if fv is None:
            continue
        parts.append(fv)
    return "[ " + ", ".join(parts) + " ]"


def write_toml_no_trailing_commas(path: str, data: dict, extra_comment_block: str = ""):
    root_scalars = {}
    root_arrays = {}
    root_tables = {}

    for k, v in data.items():
        if isinstance(v, dict):
            root_tables[k] = v
        elif isinstance(v, list):
            root_arrays[k] = v
        else:
            root_scalars[k] = v

    lines: list[str] = []

    def write_keyvals(block: dict):
        for key in sorted(block.keys()):
            val = block[key]
            if val is None:
                continue
            if isinstance(val, list):
                lines.append(f"{key} = {_toml_format_array(val)}")
            elif isinstance(val, dict):
                continue
            else:
                fv = _toml_format_scalar(val)
                if fv is None:
                    continue
                lines.append(f"{key} = {fv}")

    write_keyvals(root_scalars)
    write_keyvals(root_arrays)

    def write_table(table_path: list[str], table_dict: dict):
        local = {}
        subtables = {}

        for k, v in table_dict.items():
            if isinstance(v, dict):
                subtables[k] = v
            else:
                local[k] = v

        lines.append("")
        lines.append("[" + ".".join(table_path) + "]")
        write_keyvals(local)

        for subkey in sorted(subtables.keys()):
            write_table(table_path + [subkey], subtables[subkey])

    for tkey in sorted(root_tables.keys()):
        write_table([tkey], root_tables[tkey])

    text = "\n".join(lines).strip() + "\n"
    if extra_comment_block.strip():
        text += "\n" + extra_comment_block.strip() + "\n"

    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


# -----------------------------
# TrustTunnel deep-link helpers
# -----------------------------
def _deeplink_payload_from_uri(uri: str) -> str:
    value = str(uri or "").strip()
    if not value:
        raise ValueError("Deep link is empty.")

    if value.startswith(DEEP_LINK_PREFIX):
        payload = value[len(DEEP_LINK_PREFIX):]
    else:
        payload = value

    payload = payload.strip()
    if not payload:
        raise ValueError("Deep link payload is empty.")
    return payload


def _urlsafe_b64decode_nopad(payload: str) -> bytes:
    padding = (-len(payload)) % 4
    return base64.urlsafe_b64decode(payload + ("=" * padding))


def _read_quic_varint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of deep link payload.")

    first = data[offset]
    prefix = first >> 6
    size = 1 << prefix
    end = offset + size
    if end > len(data):
        raise ValueError("Invalid QUIC varint in deep link payload.")

    value = first & 0x3F
    for index in range(offset + 1, end):
        value = (value << 8) | data[index]
    return value, end


def _read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Invalid DER certificate chain.")

    first = data[offset]
    if first < 0x80:
        return first, offset + 1

    length_size = first & 0x7F
    if length_size == 0 or length_size > 4:
        raise ValueError("Unsupported DER certificate length.")

    end = offset + 1 + length_size
    if end > len(data):
        raise ValueError("Truncated DER certificate length.")

    length = 0
    for index in range(offset + 1, end):
        length = (length << 8) | data[index]
    return length, end


def _split_der_cert_chain(blob: bytes) -> list[bytes]:
    certs: list[bytes] = []
    offset = 0

    while offset < len(blob):
        if data := blob[offset:offset + 1]:
            if data[0] != 0x30:
                raise ValueError("Invalid DER certificate chain.")
        else:
            break

        cert_start = offset
        length, value_offset = _read_der_length(blob, offset + 1)
        cert_end = value_offset + length
        if cert_end > len(blob):
            raise ValueError("Truncated DER certificate chain.")

        certs.append(blob[cert_start:cert_end])
        offset = cert_end

    if not certs:
        raise ValueError("Certificate chain is empty.")
    return certs


def _der_cert_to_pem(cert_der: bytes) -> str:
    b64 = base64.b64encode(cert_der).decode("ascii")
    lines = [b64[index:index + 64] for index in range(0, len(b64), 64)]
    body = "\n".join(lines)
    return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"


def decode_trusttunnel_deeplink(uri: str) -> dict:
    payload = _deeplink_payload_from_uri(uri)
    data = _urlsafe_b64decode_nopad(payload)
    offset = 0
    parsed = {
        "addresses": [],
        "has_ipv6": True,
        "skip_verification": False,
        "upstream_protocol": "http2",
        "anti_dpi": False,
    }

    while offset < len(data):
        tag, offset = _read_quic_varint(data, offset)
        length, offset = _read_quic_varint(data, offset)
        end = offset + length
        if end > len(data):
            raise ValueError("Deep link contains a truncated field.")

        value = data[offset:end]
        offset = end

        if tag == 0x00:
            if len(value) != 1:
                raise ValueError("Unsupported deep link version field.")
            version = value[0]
            if version not in (0, 1):
                raise ValueError(f"Unsupported deep link version: {version}")
        elif tag == 0x01:
            parsed["hostname"] = value.decode("utf-8")
        elif tag == 0x02:
            parsed["addresses"].append(value.decode("utf-8"))
        elif tag == 0x03:
            parsed["custom_sni"] = value.decode("utf-8")
        elif tag == 0x04:
            if len(value) != 1:
                raise ValueError("Invalid has_ipv6 value in deep link.")
            parsed["has_ipv6"] = bool(value[0])
        elif tag == 0x05:
            parsed["username"] = value.decode("utf-8")
        elif tag == 0x06:
            parsed["password"] = value.decode("utf-8")
        elif tag == 0x07:
            if len(value) != 1:
                raise ValueError("Invalid skip_verification value in deep link.")
            parsed["skip_verification"] = bool(value[0])
        elif tag == 0x08:
            certs = _split_der_cert_chain(value)
            parsed["certificate"] = "".join(_der_cert_to_pem(cert) for cert in certs).strip()
        elif tag == 0x09:
            if len(value) != 1:
                raise ValueError("Invalid upstream_protocol value in deep link.")
            if value[0] == 0x01:
                parsed["upstream_protocol"] = "http2"
            elif value[0] == 0x02:
                parsed["upstream_protocol"] = "http3"
            else:
                raise ValueError("Unsupported upstream protocol in deep link.")
        elif tag == 0x0A:
            if len(value) != 1:
                raise ValueError("Invalid anti_dpi value in deep link.")
            parsed["anti_dpi"] = bool(value[0])
        elif tag == 0x0B:
            parsed["client_random"] = value.decode("utf-8")

    missing = [field for field in ("hostname", "username", "password") if not parsed.get(field)]
    if not parsed["addresses"]:
        missing.append("addresses")
    if missing:
        raise ValueError("Deep link is missing required fields: " + ", ".join(missing))

    return parsed


# -----------------------------
# Windows DPAPI helpers
# -----------------------------
class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _make_data_blob(data: bytes):
    if not data:
        return _DataBlob(0, ctypes.POINTER(ctypes.c_byte)()), None
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    return blob, buf


def _dpapi_protect_string(text: str, description: str = "") -> str:
    if os.name != "nt":
        raise OSError("Windows DPAPI is only available on Windows.")

    in_blob, in_buf = _make_data_blob(text.encode("utf-8"))
    out_blob = _DataBlob()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        description,
        None,
        None,
        None,
        0x01,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()

    try:
        protected = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)

    return base64.b64encode(protected).decode("ascii")


def _dpapi_unprotect_string(payload: str) -> str:
    if os.name != "nt":
        raise OSError("Windows DPAPI is only available on Windows.")

    raw = base64.b64decode(payload.encode("ascii"))
    in_blob, in_buf = _make_data_blob(raw)
    out_blob = _DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0x01,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()

    try:
        plain = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)

    return plain.decode("utf-8")


# -----------------------------
# Auto-elevate (UAC) - Windows only
# -----------------------------
def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_windows_gui_python_exe() -> str:
    exe = sys.executable
    if exe.lower().endswith("python.exe"):
        cand = exe[:-10] + "pythonw.exe"
        if os.path.isfile(cand):
            return cand
    return exe


def relaunch_as_admin_if_needed() -> bool:
    if os.name != "nt" or is_admin():
        return True
    try:
        params = subprocess.list2cmdline(sys.argv)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", get_windows_gui_python_exe(), params, None, 1)
    except Exception:
        pass
    return False


# -----------------------------
# Main GUI
# -----------------------------
class VpnGui(tk.Tk):
    APP_NAME = "TrustTunnel VPN"
    APP_VERSION = "1.0.2"
    SECURE_FIELDS = (
        (("endpoint", "password"), "endpoint.password"),
        (("listener", "socks", "password"), "listener.socks.password"),
    )

    BG = "#1e1e1e"
    PANEL = "#1e1e1e"
    BTN_BG = "#2b2b2b"
    BTN_BG_HOVER = "#3c3c3c"
    FG = "#ffffff"
    INPUT_BG = "#ffffff"
    INPUT_FG = "#000000"
    LOG_FG = "#d4d4d4"
    BORDER = "#3c3c3c"

    AUTOSAVE_DEBOUNCE_MS = 700
    PROC_EXIT_POLL_MS = 300
    DEFAULT_LISTENER_MODE = "socks"

    def _app_title(self) -> str:
        return f"{self.APP_NAME} v{self.APP_VERSION}"

    def _tray_status_title(self, connected: bool) -> str:
        state = "connected" if connected else "disconnected"
        return f"{self._app_title()}: {state}"

    def __init__(self, startup_args: list[str] | None = None):
        super().__init__()

        self.overrideredirect(True)
        self.configure(bg=self.BG)

        self.title(self._app_title())
        self.geometry("980x900")
        self.minsize(860, 600)

        self.proc: subprocess.Popen | None = None
        self.reader_thread: threading.Thread | None = None
        self.stop_read = threading.Event()
        self.running_listener_mode: str | None = None
        self.startup_args = list(startup_args or [])
        self.startup_deeplink = self._find_deeplink_in_args(self.startup_args)

        self._drag_offset_x = 0
        self._drag_offset_y = 0

        self.tray_icon: pystray.Icon | None = None
        self.minimize_to_tray_on_close = True
        self._initial_listener_mode = self.DEFAULT_LISTENER_MODE

        self.app_dir = get_app_dir()
        self.bundle_dir = get_bundle_dir()
        self.user_data_dir = get_user_data_dir()

        self.config_path = os.path.join(self.user_data_dir, "trusttunnel_client.toml")
        self.config: dict = {}
        self.secret_store: dict[str, str] = {}
        self.secret_store_path = self._secret_store_path_for_config(self.config_path)
        self.runtime_config_path: str | None = None
        self._autosave_job = None

        self.icon_path = self._find_resource_file("icon.png", required=False)

        self.load_config()

        self.exe_path = tk.StringVar(value=self._default_client_exe_path())
        self.cfg_path = tk.StringVar(value=self.config_path)

        self._apply_dark_theme()
        self._build_ui()
        self._append_log(f"[INFO] {self._app_title()} started.\n")

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._refresh_ready_status()

        self.after(300, self._ensure_tray)
        self.after(self.PROC_EXIT_POLL_MS, self._poll_process_exit)
        if self.startup_deeplink:
            self.after(350, self._import_startup_deeplink)

    def _find_resource_file(self, filename: str, required: bool = True) -> str:
        candidates = [
            os.path.join(self.bundle_dir, filename),
            os.path.join(self.app_dir, filename),
            os.path.join(self.user_data_dir, filename),
        ]
        for path in candidates:
            if path and os.path.isfile(path):
                return path
        return candidates[0] if required else ""

    def _default_client_exe_path(self) -> str:
        return self._find_resource_file("trusttunnel_client.exe", required=False)

    def _load_embedded_template_config(self) -> dict | None:
        template_path = self._find_resource_file("trusttunnel_client.toml", required=False)
        if not template_path or not os.path.isfile(template_path):
            return None
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                loaded = toml.load(f)
            return loaded if isinstance(loaded, dict) else None
        except Exception:
            tray_log_error("EMBEDDED CONFIG LOAD ERROR")
            return None

    # -----------------------------
    # Dark theme
    # -----------------------------
    def _apply_dark_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background=self.BG, foreground=self.FG)
        style.configure("TFrame", background=self.BG)
        style.configure("TLabel", background=self.BG, foreground=self.FG)
        style.configure("TLabelframe", background=self.BG, foreground=self.FG)
        style.configure("TLabelframe.Label", background=self.BG, foreground=self.FG)
        style.configure("TNotebook", background=self.BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.INPUT_BG, foreground=self.INPUT_FG, padding=(12, 6))
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.INPUT_BG), ("active", "#e8e8e8")],
            foreground=[("selected", self.INPUT_FG), ("active", self.INPUT_FG)],
        )

        style.configure("TButton", background=self.BTN_BG, foreground=self.FG, borderwidth=1)
        style.map("TButton", background=[("active", self.BTN_BG_HOVER)])

        style.configure("TEntry", fieldbackground=self.INPUT_BG, foreground=self.INPUT_FG)
        style.configure(
            "TCombobox",
            fieldbackground=self.INPUT_BG,
            background=self.INPUT_BG,
            foreground=self.INPUT_FG,
            arrowcolor=self.INPUT_FG,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", self.INPUT_BG), ("disabled", "#d9d9d9")],
            background=[("readonly", self.INPUT_BG), ("disabled", "#d9d9d9")],
            foreground=[("readonly", self.INPUT_FG), ("disabled", "#666666")],
            selectforeground=[("readonly", self.INPUT_FG)],
            selectbackground=[("readonly", self.INPUT_BG)],
            arrowcolor=[("readonly", self.INPUT_FG), ("disabled", "#666666")],
        )

        style.configure("TCheckbutton", background=self.BG, foreground=self.FG)
        style.map("TCheckbutton", background=[("active", self.BG)])

        style.configure("Treeview", background=self.BTN_BG, foreground=self.FG, fieldbackground=self.BTN_BG)

    # -----------------------------
    # Config
    # -----------------------------
    def _default_config(self) -> dict:
        return {
            "loglevel": "info",
            "vpn_mode": "general",
            "killswitch_enabled": True,
            "killswitch_allow_ports": [],
            "post_quantum_group_enabled": True,
            "exclusions": [
                "youtube.com",
                "*.youtube.com",
                "youtu.be",
                "*.youtu.be",
                "googlevideo.com",
                "*.googlevideo.com",
                "ytimg.com",
                "*.ytimg.com",
                "youtubei.googleapis.com",
                "*.youtubei.googleapis.com",
                "ggpht.com",
                "*.ggpht.com",
                "googleusercontent.com",
                "*.googleusercontent.com",
            ],
            "dns_upstreams": ["tls://1.1.1.1", "tcp://8.8.8.8:53"],
            "endpoint": {
                "hostname": "Your hostname DNS",
                "addresses": ["Your IP:443"],
                "has_ipv6": True,
                "username": "Your login",
                "password": "",
                "client_random": "",
                "skip_verification": False,
                "upstream_protocol": "http2",
                "upstream_fallback_protocol": "",
                "anti_dpi": False,
            },
            "listener": {
                "tun": {
                    "bound_if": "",
                    "included_routes": ["0.0.0.0/0", "2000::/3"],
                    "excluded_routes": [
                        "0.0.0.0/8",
                        "10.0.0.0/8",
                        "169.254.0.0/16",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "224.0.0.0/3",
                    ],
                    "mtu_size": 1280,
                    "change_system_dns": True,
                },
                "socks": {
                    "address": "127.0.0.1:1080",
                    "username": "",
                    "password": "",
                },
            },
        }

    def load_config(self):
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = toml.load(f)
                self._initial_listener_mode = self._detect_listener_mode(self.config)
            else:
                template_cfg = self._load_embedded_template_config()
                if isinstance(template_cfg, dict):
                    self.config = template_cfg
                    self._initial_listener_mode = self._detect_listener_mode(
                        self.config,
                        fallback=self.DEFAULT_LISTENER_MODE,
                    )
                else:
                    self.config = self._default_config()
                    self._initial_listener_mode = self.DEFAULT_LISTENER_MODE
        except Exception as e:
            messagebox.showerror("Config Error", f"Failed to load config:\n{str(e)}")
            self.config = self._default_config()
            self._initial_listener_mode = self.DEFAULT_LISTENER_MODE

        self.secret_store = self._load_secret_store()
        self._migrate_legacy_secret_store_if_needed()
        defaults = self._default_config()

        if "listener" not in self.config or not isinstance(self.config["listener"], dict):
            self.config["listener"] = {}
        self.config["listener"].setdefault("tun", defaults["listener"]["tun"])
        self.config["listener"].setdefault("socks", defaults["listener"]["socks"])

        if "exclusions" not in self.config or not isinstance(self.config["exclusions"], list):
            self.config["exclusions"] = list(defaults["exclusions"])

        migrated = self._migrate_plaintext_secrets_to_secure_store()
        self._apply_secure_values_to_config()

        if migrated or not os.path.exists(self.config_path):
            self.save_config(silent=True)

    def save_config(self, silent: bool = False):
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            self._persist_secure_values_from_config()

            effective = self._build_effective_config_for_save()
            extra = self._build_inactive_listener_comment_block(include_sensitive=False)

            write_toml_no_trailing_commas(self.config_path, effective, extra_comment_block=extra)

            if not silent:
                self._append_log("[INFO] Configuration saved.\n")
        except Exception as e:
            messagebox.showerror("Config Error", f"Failed to save config:\n{str(e)}")
            if not silent:
                self._append_log(f"[ERROR] Config save failed: {e}\n")

    def _detect_listener_mode(self, config: dict | None = None, fallback: str | None = None) -> str:
        listener = config.get("listener", {}) if isinstance(config, dict) else {}
        fallback = fallback or self.DEFAULT_LISTENER_MODE
        if isinstance(listener, dict):
            has_socks = "socks" in listener and isinstance(listener.get("socks"), dict)
            has_tun = "tun" in listener and isinstance(listener.get("tun"), dict)
            if has_socks and not has_tun:
                return "socks"
            if has_tun and not has_socks:
                return "tun"
        return fallback

    def _detect_listener_mode_from_config(self) -> str:
        return self._detect_listener_mode(
            self.config,
            fallback=getattr(self, "_initial_listener_mode", self.DEFAULT_LISTENER_MODE),
        )

    def _selected_listener_mode(self) -> str:
        mode_var = getattr(self, "listener_mode_var", None)
        mode = mode_var.get() if mode_var else self._detect_listener_mode_from_config()
        mode = str(mode or "").strip().lower()
        return mode if mode in {"tun", "socks"} else self.DEFAULT_LISTENER_MODE

    def _refresh_listener_status(self):
        if not hasattr(self, "listener_status"):
            return

        selected_mode = self._selected_listener_mode()
        running_mode = self.running_listener_mode

        if running_mode:
            if selected_mode != running_mode:
                text = f"Listener: {running_mode} (running, selected {selected_mode})"
            else:
                text = f"Listener: {running_mode} (running)"
        else:
            text = f"Listener: {selected_mode} (selected)"

        self.listener_status.set(text)

    def _find_deeplink_in_args(self, args: list[str]) -> str:
        for arg in args:
            value = str(arg or "").strip()
            if value.startswith(DEEP_LINK_PREFIX):
                return value
        return ""

    def _make_deeplink_summary(self, decoded: dict) -> str:
        lines = [
            "Apply TrustTunnel deep link to the current configuration?",
            "",
            f"Hostname: {decoded['hostname']}",
            f"Addresses: {', '.join(decoded['addresses'])}",
            f"Username: {decoded['username']}",
            f"Upstream protocol: {decoded.get('upstream_protocol', 'http2')}",
            f"IPv6 support: {'yes' if decoded.get('has_ipv6', True) else 'no'}",
            f"Certificate embedded: {'yes' if decoded.get('certificate') else 'no'}",
        ]
        if decoded.get("custom_sni"):
            lines.append(f"Custom SNI: {decoded['custom_sni']}")
        if decoded.get("client_random"):
            lines.append(f"Client random: {decoded['client_random']}")
        return "\n".join(lines)

    def _apply_deeplink_to_config(self, decoded: dict):
        endpoint = self.config.setdefault("endpoint", {})
        listener = self.config.setdefault("listener", {})
        listener.setdefault("socks", {})
        listener.setdefault("tun", {})

        endpoint["hostname"] = decoded["hostname"]
        endpoint["addresses"] = list(decoded["addresses"])
        endpoint["username"] = decoded["username"]
        endpoint["password"] = decoded["password"]
        endpoint["has_ipv6"] = bool(decoded.get("has_ipv6", True))
        endpoint["skip_verification"] = bool(decoded.get("skip_verification", False))
        endpoint["upstream_protocol"] = decoded.get("upstream_protocol", "http2")
        endpoint["anti_dpi"] = bool(decoded.get("anti_dpi", False))

        if decoded.get("custom_sni"):
            endpoint["custom_sni"] = decoded["custom_sni"]
        else:
            endpoint.pop("custom_sni", None)

        if decoded.get("certificate"):
            endpoint["certificate"] = decoded["certificate"]
        else:
            endpoint.pop("certificate", None)

        if decoded.get("client_random"):
            endpoint["client_random"] = decoded["client_random"]
        else:
            endpoint["client_random"] = ""

    def _sync_deeplink_fields_from_config(self):
        if hasattr(self, "hostname_var"):
            self.hostname_var.set(self._get_nested(self.config, "endpoint", "hostname", default=""))
        if hasattr(self, "addresses_var"):
            self.addresses_var.set(", ".join(self._get_nested(self.config, "endpoint", "addresses", default=[])))
        if hasattr(self, "username_var"):
            self.username_var.set(self._get_nested(self.config, "endpoint", "username", default=""))
        if hasattr(self, "password_var"):
            self.password_var.set(self._get_nested(self.config, "endpoint", "password", default=""))
        if hasattr(self, "skip_verification_var"):
            self.skip_verification_var.set(bool(self._get_nested(self.config, "endpoint", "skip_verification", default=False)))
        if hasattr(self, "upstream_protocol_var"):
            self.upstream_protocol_var.set(self._get_nested(self.config, "endpoint", "upstream_protocol", default="http2"))
        if hasattr(self, "anti_dpi_var"):
            self.anti_dpi_var.set(bool(self._get_nested(self.config, "endpoint", "anti_dpi", default=False)))

    def import_deeplink(self, uri: str | None = None, source: str = "manual") -> bool:
        deeplink_var = getattr(self, "deeplink_var", None)
        raw_value = uri if uri is not None else (deeplink_var.get() if deeplink_var is not None else "")
        try:
            decoded = decode_trusttunnel_deeplink(raw_value)
        except Exception as exc:
            messagebox.showerror("Deep Link Error", f"Failed to parse TrustTunnel deep link:\n{exc}")
            return False

        if not messagebox.askyesno("Import TrustTunnel Deep Link", self._make_deeplink_summary(decoded)):
            return False

        self._apply_deeplink_to_config(decoded)
        self._sync_deeplink_fields_from_config()
        self.save_config(silent=True)
        self._refresh_ready_status()

        if hasattr(self, "deeplink_var"):
            self.deeplink_var.set("")

        self._append_log(
            f"[INFO] Imported TrustTunnel deep link from {source}: "
            f"{decoded['hostname']} ({len(decoded['addresses'])} address{'es' if len(decoded['addresses']) != 1 else ''}).\n"
        )
        messagebox.showinfo("Deep Link Imported", "Configuration fields were updated from the TrustTunnel deep link.")
        return True

    def _import_startup_deeplink(self):
        if not self.startup_deeplink:
            return
        if hasattr(self, "deeplink_var"):
            self.deeplink_var.set(self.startup_deeplink)
        self.import_deeplink(self.startup_deeplink, source="command line")
        self.startup_deeplink = ""

    def _build_effective_config_for_save(self, include_sensitive: bool = False) -> dict:
        mode_var = getattr(self, "listener_mode_var", None)
        listener_mode = mode_var.get() if mode_var else self._detect_listener_mode_from_config()

        out = copy.deepcopy(self.config)
        listener_out = {}
        listener_in = out.get("listener", {}) if isinstance(out.get("listener"), dict) else {}

        if listener_mode == "socks":
            listener_out["socks"] = dict(listener_in.get("socks", {}))
        else:
            listener_out["tun"] = dict(listener_in.get("tun", {}))

        out["listener"] = listener_out
        if not include_sensitive:
            self._strip_secure_values_from_config(out)
        return out

    def _make_commented_table_block(self, table_name: str, table_dict: dict) -> str:
        lines = [f"# [{table_name}]"]
        for k in sorted(table_dict.keys()):
            v = table_dict[k]
            if isinstance(v, list):
                lines.append(f"# {k} = {_toml_format_array(v)}")
            else:
                fv = _toml_format_scalar(v)
                if fv is None:
                    continue
                lines.append(f"# {k} = {fv}")
        return "\n".join(lines)

    def _build_inactive_listener_comment_block(self, include_sensitive: bool = False) -> str:
        mode_var = getattr(self, "listener_mode_var", None)
        listener_mode = mode_var.get() if mode_var else self._detect_listener_mode_from_config()

        if listener_mode == "socks":
            tun = self._get_nested(self.config, "listener", "tun", default={})
            return self._make_commented_table_block("listener.tun", tun)
        else:
            socks = copy.deepcopy(self._get_nested(self.config, "listener", "socks", default={}))
            if not socks:
                socks = {"address": "127.0.0.1:1080", "username": "", "password": ""}
            if isinstance(socks, dict) and not include_sensitive:
                socks["password"] = ""
            return self._make_commented_table_block("listener.socks", socks)

    def _secure_store_dir(self) -> str:
        path = os.path.join(self.user_data_dir, "secure_store")
        os.makedirs(path, exist_ok=True)
        return path

    def _secret_store_path_for_config(self, config_path: str) -> str:
        config_id = hashlib.sha256(os.path.abspath(config_path).encode("utf-8")).hexdigest()[:16]
        return os.path.join(self._secure_store_dir(), f"{config_id}.bin")

    def _load_secret_store_from_file(self, store_path: str) -> dict[str, str]:
        if not os.path.exists(store_path):
            return {}
        try:
            with open(store_path, "r", encoding="ascii") as f:
                payload = f.read().strip()
            if not payload:
                return {}

            data = json.loads(_dpapi_unprotect_string(payload))
            values = data.get("values", {}) if isinstance(data, dict) else {}
            if not isinstance(values, dict):
                return {}
            return {str(k): str(v) for k, v in values.items() if v is not None}
        except Exception:
            tray_log_error("SECURE STORE LOAD ERROR")
            return {}

    def _load_secret_store(self) -> dict[str, str]:
        self.secret_store_path = self._secret_store_path_for_config(self.config_path)
        return self._load_secret_store_from_file(self.secret_store_path)

    def _legacy_config_candidates(self) -> list[str]:
        candidates = [
            os.path.join(self.app_dir, "trusttunnel_client.toml"),
            os.path.join(self.bundle_dir, "trusttunnel_client.toml"),
        ]
        dedup = []
        current_abs = os.path.abspath(self.config_path)
        for path in candidates:
            if not path:
                continue
            ap = os.path.abspath(path)
            if ap == current_abs:
                continue
            if ap not in dedup:
                dedup.append(ap)
        return dedup

    def _migrate_legacy_secret_store_if_needed(self):
        if any(self.secret_store.get(secret_key) for _path, secret_key in self.SECURE_FIELDS):
            return

        for legacy_cfg in self._legacy_config_candidates():
            legacy_store = self._secret_store_path_for_config(legacy_cfg)
            migrated_values = self._load_secret_store_from_file(legacy_store)

            if not migrated_values and os.path.isfile(legacy_cfg):
                try:
                    legacy_config = toml.load(legacy_cfg)
                    if isinstance(legacy_config, dict):
                        for path, secret_key in self.SECURE_FIELDS:
                            value = str(self._get_nested(legacy_config, *path, default="") or "")
                            if value:
                                migrated_values[secret_key] = value
                except Exception:
                    tray_log_error("LEGACY CONFIG READ ERROR")

            merged = False
            for _path, secret_key in self.SECURE_FIELDS:
                value = str(migrated_values.get(secret_key, "") or "")
                if value and not self.secret_store.get(secret_key):
                    self.secret_store[secret_key] = value
                    merged = True

            if merged:
                self._save_secret_store()
                return

    def _save_secret_store(self):
        self.secret_store_path = self._secret_store_path_for_config(self.config_path)
        values = {k: v for k, v in self.secret_store.items() if str(v)}

        if not values:
            try:
                if os.path.exists(self.secret_store_path):
                    os.remove(self.secret_store_path)
            except Exception:
                tray_log_error("SECURE STORE DELETE ERROR")
            return

        payload = json.dumps({"version": 1, "values": values}, ensure_ascii=True)
        os.makedirs(os.path.dirname(self.secret_store_path), exist_ok=True)
        with open(self.secret_store_path, "w", encoding="ascii", newline="\n") as f:
            f.write(_dpapi_protect_string(payload, description=self._app_title()))

    def _set_secret_value(self, secret_key: str, value: str):
        value = str(value or "")
        if value:
            self.secret_store[secret_key] = value
        else:
            self.secret_store.pop(secret_key, None)

    def _persist_secure_values_from_config(self):
        for path, secret_key in self.SECURE_FIELDS:
            value = str(self._get_nested(self.config, *path, default="") or "")
            self._set_secret_value(secret_key, value)
        self._save_secret_store()

    def _apply_secure_values_to_config(self):
        for path, secret_key in self.SECURE_FIELDS:
            self._set_nested(self.config, *path, self.secret_store.get(secret_key, ""))

    def _migrate_plaintext_secrets_to_secure_store(self) -> bool:
        migrated = False
        for path, secret_key in self.SECURE_FIELDS:
            value = str(self._get_nested(self.config, *path, default="") or "")
            if value:
                self._set_secret_value(secret_key, value)
                migrated = True

        if migrated:
            self._save_secret_store()
        return migrated

    def _strip_secure_values_from_config(self, config: dict):
        for path, _secret_key in self.SECURE_FIELDS:
            self._set_nested_if_present(config, *path, "")

    def _create_runtime_config(self) -> str:
        self._cleanup_runtime_config()

        runtime_config = self._build_effective_config_for_save(include_sensitive=True)
        extra = self._build_inactive_listener_comment_block(include_sensitive=True)

        fd, runtime_path = tempfile.mkstemp(prefix="trusttunnel_runtime_", suffix=".toml")
        os.close(fd)
        write_toml_no_trailing_commas(runtime_path, runtime_config, extra_comment_block=extra)
        self.runtime_config_path = runtime_path
        return runtime_path

    def _cleanup_runtime_config(self):
        if not self.runtime_config_path:
            return
        try:
            if os.path.exists(self.runtime_config_path):
                os.remove(self.runtime_config_path)
        except Exception:
            tray_log_error("RUNTIME CONFIG CLEANUP ERROR")
        finally:
            self.runtime_config_path = None

    # -----------------------------
    # Autosave
    # -----------------------------
    def _schedule_autosave(self):
        if self._autosave_job is not None:
            try:
                self.after_cancel(self._autosave_job)
            except Exception:
                pass
            self._autosave_job = None
        self._autosave_job = self.after(self.AUTOSAVE_DEBOUNCE_MS, self._autosave_now)

    def _autosave_now(self):
        self._autosave_job = None
        self.save_config(silent=True)

    # -----------------------------
    # Nested helpers
    # -----------------------------
    def _get_nested(self, d, *keys, default=None):
        for key in keys:
            if isinstance(d, dict) and key in d:
                d = d[key]
            else:
                return default
        return d

    def _ensure_path_dicts(self, root: dict, *path):
        d = root
        for key in path:
            if key not in d or not isinstance(d[key], dict):
                d[key] = {}
            d = d[key]
        return d

    def _set_nested(self, d, *keys):
        value = keys[-1]
        keys = keys[:-1]
        if not keys:
            return
        if len(keys) == 1:
            d[keys[0]] = value
            return
        parent = self._ensure_path_dicts(d, *keys[:-1])
        parent[keys[-1]] = value

    def _set_nested_if_present(self, d, *keys):
        value = keys[-1]
        keys = keys[:-1]
        if not keys or not isinstance(d, dict):
            return
        if len(keys) == 1:
            if keys[0] in d:
                d[keys[0]] = value
            return

        parent = d
        for key in keys[:-1]:
            if key not in parent or not isinstance(parent[key], dict):
                return
            parent = parent[key]

        if keys[-1] in parent:
            parent[keys[-1]] = value

    # -----------------------------
    # UI bind helpers
    # -----------------------------
    def _create_string_var(self, *path, default=""):
        value = self._get_nested(self.config, *path, default=default)
        var = tk.StringVar(value=str(value))

        def on_change(*_):
            self._set_nested(self.config, *path, var.get())
            self._schedule_autosave()

        var.trace_add("write", on_change)
        return var

    def _create_bool_var(self, *path, default=False):
        value = self._get_nested(self.config, *path, default=default)
        var = tk.BooleanVar(value=bool(value))

        def on_change(*_):
            self._set_nested(self.config, *path, bool(var.get()))
            self._schedule_autosave()

        var.trace_add("write", on_change)
        return var

    def _create_int_var(self, *path, default=0):
        value = self._get_nested(self.config, *path, default=default)
        try:
            iv = int(value)
        except Exception:
            iv = int(default)

        var = tk.StringVar(value=str(iv))

        def on_change(*_):
            s = var.get().strip()
            if s == "":
                return
            try:
                n = int(s)
            except ValueError:
                return
            self._set_nested(self.config, *path, n)
            self._schedule_autosave()

        var.trace_add("write", on_change)
        return var

    def _create_root_string_var(self, key: str, default=""):
        value = self.config.get(key, default)
        var = tk.StringVar(value=str(value))

        def on_change(*_):
            self.config[key] = var.get()
            self._schedule_autosave()

        var.trace_add("write", on_change)
        return var

    def _create_root_bool_var(self, key: str, default=False):
        value = bool(self.config.get(key, default))
        var = tk.BooleanVar(value=value)

        def on_change(*_):
            self.config[key] = bool(var.get())
            self._schedule_autosave()

        var.trace_add("write", on_change)
        return var

    def _split_list(self, s: str) -> list[str]:
        return [x.strip() for x in s.split(",") if x.strip()]

    def _split_cmdline(self, s: str) -> list[str]:
        s = (s or "").strip()
        if not s:
            return []
        try:
            if os.name == "nt":
                return shlex.split(s, posix=False)
            return shlex.split(s)
        except Exception:
            return s.split()

    def _edit_list(self, title: str, items: list, on_saved=None):
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry("450x320")
        dialog.configure(bg=self.BG)
        dialog.transient(self)
        dialog.grab_set()

        tk.Label(dialog, text="Edit items (one per line):", bg=self.BG, fg=self.FG).pack(pady=(10, 5))

        text = tk.Text(dialog, bg=self.BTN_BG, fg=self.FG, height=15, insertbackground=self.FG)
        text.pack(fill="both", expand=True, padx=10, pady=5)
        text.insert("1.0", "\n".join(str(x) for x in items))

        def save():
            new_items = [line.strip() for line in text.get("1.0", "end-1c").splitlines() if line.strip()]
            items[:] = new_items
            if callable(on_saved):
                on_saved()
            self._schedule_autosave()
            dialog.destroy()

        btn_frame = tk.Frame(dialog, bg=self.BG)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Save", command=save, bg=self.BTN_BG, fg=self.FG).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy, bg=self.BTN_BG, fg=self.FG).pack(side="left", padx=5)

    # -----------------------------
    # Scrollable helper
    # -----------------------------
    def _make_scrollable(self, parent: ttk.Frame):
        canvas = tk.Canvas(parent, bg=self.BG, highlightthickness=0)
        vbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vbar.set)

        vbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = ttk.Frame(canvas)
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_configure_inner(_):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_configure_canvas(_):
            canvas.itemconfigure(window_id, width=canvas.winfo_width())

        inner.bind("<Configure>", on_configure_inner)
        canvas.bind("<Configure>", on_configure_canvas)

        def _on_mousewheel(event):
            if event.delta:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _on_linux_scroll_up(_event):
            canvas.yview_scroll(-1, "units")

        def _on_linux_scroll_down(_event):
            canvas.yview_scroll(1, "units")

        def bind_wheel(_event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", _on_linux_scroll_up)
            canvas.bind_all("<Button-5>", _on_linux_scroll_down)

        def unbind_wheel(_event):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", bind_wheel)
        canvas.bind("<Leave>", unbind_wheel)

        return canvas, inner

    # -----------------------------
    # Custom title bar
    # -----------------------------
    def _build_title_bar(self, parent):
        bar = tk.Frame(parent, bg=self.PANEL, highlightthickness=1, highlightbackground=self.BORDER)
        bar.pack(fill="x")

        title = tk.Label(
            bar,
            text=self._app_title(),
            bg=self.PANEL,
            fg=self.FG,
            font=("Segoe UI", 11, "bold"),
            padx=10,
            pady=8,
        )
        title.pack(side="left")

        for w in (bar, title):
            w.bind("<ButtonPress-1>", self._start_move)
            w.bind("<B1-Motion>", self._do_move)

        btn_min = tk.Label(bar, text="—", bg=self.BTN_BG, fg=self.FG, width=4, cursor="hand2")
        btn_close = tk.Label(bar, text="✕", bg=self.BTN_BG, fg=self.FG, width=4, cursor="hand2")
        btn_close.pack(side="right", padx=(0, 6), pady=6)
        btn_min.pack(side="right", padx=(0, 6), pady=6)

        btn_min.bind("<Button-1>", lambda e: self._minimize())
        btn_close.bind("<Button-1>", lambda e: self._on_close())

        btn_min.bind("<Enter>", lambda e: btn_min.configure(bg=self.BTN_BG_HOVER))
        btn_min.bind("<Leave>", lambda e: btn_min.configure(bg=self.BTN_BG))
        btn_close.bind("<Enter>", lambda e: btn_close.configure(bg="#b32626"))
        btn_close.bind("<Leave>", lambda e: btn_close.configure(bg=self.BTN_BG))

    def _start_move(self, event):
        self._drag_offset_x = event.x
        self._drag_offset_y = event.y

    def _do_move(self, event):
        x = self.winfo_pointerx() - self._drag_offset_x
        y = self.winfo_pointery() - self._drag_offset_y
        self.geometry(f"+{x}+{y}")

    def _minimize(self):
        self.overrideredirect(False)
        self.iconify()
        self.after(10, lambda: self.overrideredirect(True))

    # -----------------------------
    # Tray
    # -----------------------------
    def _create_tray_image(self, connected: bool = False):
        img = Image.new("RGB", (64, 64), (30, 30, 30))
        d = ImageDraw.Draw(img)
        d.rectangle((8, 8, 56, 56), outline=(200, 200, 200), width=3)
        d.text((18, 22), "VPN", fill=(255, 255, 255))
        dot = (0, 200, 0) if connected else (120, 120, 120)
        d.ellipse((46, 46, 58, 58), fill=dot)
        return img

    def _tray_menu(self):
        return pystray.Menu(
            pystray.MenuItem("Open", lambda icon, item: self.after(0, self._restore_from_tray)),
            pystray.MenuItem("Connect", lambda icon, item: self.after(0, self.start_vpn)),
            pystray.MenuItem("Disconnect", lambda icon, item: self.after(0, self.stop_vpn)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", lambda icon, item: self.after(0, self._exit_app)),
        )

    def _ensure_tray(self):
        if self.tray_icon is not None:
            return
        try:
            self.tray_icon = pystray.Icon(
                self._app_title(),
                self._create_tray_image(connected=bool(self.proc and self.proc.poll() is None)),
                self._tray_status_title(connected=bool(self.proc and self.proc.poll() is None)),
                self._tray_menu(),
            )
            self.tray_icon.run_detached()
        except Exception:
            tray_log_error("TRAY START ERROR")

    def _update_tray_status(self):
        connected = bool(self.proc and self.proc.poll() is None)
        try:
            if self.tray_icon:
                self.tray_icon.icon = self._create_tray_image(connected=connected)
                self.tray_icon.title = self._tray_status_title(connected)
        except Exception:
            tray_log_error("TRAY UPDATE ERROR")

    def _minimize_to_tray(self):
        self._ensure_tray()
        self.withdraw()

    def _restore_from_tray(self):
        self.overrideredirect(False)
        self.deiconify()
        self.lift()
        self.focus_force()
        self.after(10, lambda: self.overrideredirect(True))

    # -----------------------------
    # Browser / app launch helpers
    # -----------------------------
    def _find_chrome(self) -> str:
        cands = [
            os.path.join(os.environ.get("ProgramFiles", ""), r"Google\Chrome\Application\chrome.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), r"Google\Chrome\Application\chrome.exe"),
            os.path.join(os.environ.get("LocalAppData", ""), r"Google\Chrome\Application\chrome.exe"),
        ]
        for p in cands:
            if p and os.path.isfile(p):
                return p
        return ""

    def _find_edge(self) -> str:
        cands = [
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), r"Microsoft\Edge\Application\msedge.exe"),
            os.path.join(os.environ.get("ProgramFiles", ""), r"Microsoft\Edge\Application\msedge.exe"),
            os.path.join(os.environ.get("LocalAppData", ""), r"Microsoft\Edge\Application\msedge.exe"),
        ]
        for p in cands:
            if p and os.path.isfile(p):
                return p
        return ""

    def _find_firefox(self) -> str:
        cands = [
            os.path.join(os.environ.get("ProgramFiles", ""), r"Mozilla Firefox\firefox.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), r"Mozilla Firefox\firefox.exe"),
            os.path.join(os.environ.get("LocalAppData", ""), r"Mozilla Firefox\firefox.exe"),
        ]
        for p in cands:
            if p and os.path.isfile(p):
                return p
        return ""

    def _find_yandex(self) -> str:
        cands = [
            os.path.join(os.environ.get("LocalAppData", ""), r"Yandex\YandexBrowser\Application\browser.exe"),
            os.path.join(os.environ.get("ProgramFiles", ""), r"Yandex\YandexBrowser\Application\browser.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), r"Yandex\YandexBrowser\Application\browser.exe"),
        ]
        for p in cands:
            if p and os.path.isfile(p):
                return p
        return ""

    def _find_vscode(self) -> str:
        cands = [
            os.path.join(os.environ.get("LocalAppData", ""), r"Programs\Microsoft VS Code\Code.exe"),
            os.path.join(os.environ.get("ProgramFiles", ""), r"Microsoft VS Code\Code.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), r"Microsoft VS Code\Code.exe"),
        ]
        for p in cands:
            if p and os.path.isfile(p):
                return p
        return ""

    def _build_proxy_env(self, socks_url: str) -> dict:
        env = os.environ.copy()
        env["ALL_PROXY"] = socks_url
        env["HTTP_PROXY"] = socks_url
        env["HTTPS_PROXY"] = socks_url
        env["all_proxy"] = socks_url
        env["http_proxy"] = socks_url
        env["https_proxy"] = socks_url
        env.setdefault("NO_PROXY", "localhost,127.0.0.1")
        env.setdefault("no_proxy", "localhost,127.0.0.1")
        return env

    def _get_socks_addr(self) -> str:
        addr = self._get_nested(self.config, "listener", "socks", "address", default="127.0.0.1:1080")
        addr = str(addr).strip()
        return addr if addr else "127.0.0.1:1080"

    def _get_socks_host_port(self) -> tuple[str, int]:
        addr = self._get_socks_addr()
        host, port = addr.rsplit(":", 1)
        host = host.strip().strip("[]")
        try:
            return host or "127.0.0.1", int(port)
        except ValueError:
            return "127.0.0.1", 1080

    def _ensure_running_socks_mode(self) -> bool:
        if not (self.proc and self.proc.poll() is None):
            messagebox.showinfo("Info", "VPN is not running. Click Connect first.")
            return False

        mode = getattr(self, "listener_mode_var", None).get() if getattr(self, "listener_mode_var", None) else "tun"
        if mode != "socks":
            messagebox.showwarning(
                "SOCKS required",
                "To run an application via SOCKS, set Listener Type = socks and reconnect.\n\n"
                "TUN mode does not expose a local SOCKS proxy."
            )
            return False
        return True

    def launch_browser_via_vpn(self, browser: str):
        """
        Запуск Chrome/Edge через SOCKS.

        Важно:
        TrustTunnel поднимает либо TUN, либо SOCKS listener.
        Чтобы браузер реально шёл через SOCKS, нужно выбрать Listener Type = socks и подключиться.
        """
        if not self._ensure_running_socks_mode():
            return

        if browser == "firefox":
            self.launch_firefox_via_vpn()
            return

        finder_map = {
            "chrome": self._find_chrome,
            "edge": self._find_edge,
            "yandex": self._find_yandex,
        }
        finder = finder_map.get(browser)
        if finder is None:
            messagebox.showerror("Error", f"Unsupported browser: {browser}")
            return

        exe = finder()
        if not exe:
            messagebox.showerror("Error", f"{browser} not found (not installed in default paths).")
            return

        socks = self._get_socks_addr()

        profile_dir = os.path.join(self.user_data_dir, "browser_profiles", browser)
        os.makedirs(profile_dir, exist_ok=True)

        args = [
            exe,
            f"--proxy-server=socks5://{socks}",
            f"--user-data-dir={profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--restore-last-session",
        ]

        try:
            subprocess.Popen(args, cwd=os.path.dirname(exe) or None)
            self._append_log(f"[INFO] Started {browser} via SOCKS {socks}\n")
        except Exception as e:
            messagebox.showerror("Launch error", str(e))
            self._append_log(f"[ERROR] Failed to start {browser}: {e}\n")

    def _write_firefox_proxy_profile(self, profile_dir: str, socks_host: str, socks_port: int):
        os.makedirs(profile_dir, exist_ok=True)
        user_js_path = os.path.join(profile_dir, "user.js")
        lines = [
            'user_pref("network.proxy.type", 1);',
            f'user_pref("network.proxy.socks", "{socks_host}");',
            f'user_pref("network.proxy.socks_port", {socks_port});',
            'user_pref("network.proxy.socks_version", 5);',
            'user_pref("network.proxy.socks_remote_dns", true);',
            'user_pref("network.proxy.no_proxies_on", "");',
            'user_pref("network.trr.mode", 5);',
        ]
        with open(user_js_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    def launch_firefox_via_vpn(self):
        if not self._ensure_running_socks_mode():
            return

        exe = self._find_firefox()
        if not exe:
            messagebox.showerror("Error", "firefox not found (not installed in default paths).")
            return

        socks = self._get_socks_addr()
        socks_host, socks_port = self._get_socks_host_port()
        profile_dir = os.path.join(self.user_data_dir, "browser_profiles", "firefox")
        self._write_firefox_proxy_profile(profile_dir, socks_host, socks_port)

        args = [
            exe,
            "-new-instance",
            "-no-remote",
            "-profile",
            profile_dir,
        ]

        try:
            subprocess.Popen(
                args,
                cwd=os.path.dirname(exe) or None,
                env=self._build_proxy_env(f"socks5://{socks}"),
            )
            self._append_log(f"[INFO] Started firefox via SOCKS {socks}\n")
        except Exception as e:
            messagebox.showerror("Launch error", str(e))
            self._append_log(f"[ERROR] Failed to start firefox: {e}\n")

    def launch_vscode_via_vpn(self):
        if not self._ensure_running_socks_mode():
            return

        exe = self._find_vscode()
        if not exe:
            messagebox.showerror("Error", "VS Code not found (Code.exe is not installed in default paths).")
            return

        socks = self._get_socks_addr()
        socks_url = f"socks5://{socks}"
        profile_dir = os.path.join(self.user_data_dir, "vscode_profile")
        os.makedirs(profile_dir, exist_ok=True)

        args = [
            exe,
            "--new-window",
            f"--proxy-server={socks_url}",
            f"--user-data-dir={profile_dir}",
        ]

        try:
            subprocess.Popen(
                args,
                cwd=os.path.dirname(exe) or None,
                env=self._build_proxy_env(socks_url),
            )
            self._append_log(f"[INFO] Started VS Code via SOCKS {socks}\n")
        except Exception as e:
            messagebox.showerror("Launch error", str(e))
            self._append_log(f"[ERROR] Failed to start VS Code: {e}\n")

    def _browse_custom_app(self):
        p = filedialog.askopenfilename(
            title="Select application exe",
            filetypes=[("Executable", "*.exe"), ("All files", "*.*")]
        )
        if p:
            self.custom_app_path_var.set(p)

    def launch_custom_app_via_vpn(self):
        """
        Универсальный запуск произвольного приложения через SOCKS.

        Как работает:
        - в аргументах можно использовать плейсхолдер {socks}
        - в окружение выставляются ALL_PROXY / HTTP_PROXY / HTTPS_PROXY

        Ограничение:
        это сработает только для приложений, которые поддерживают proxy
        через аргументы или через переменные окружения.
        """
        if not self._ensure_running_socks_mode():
            return

        exe = self.custom_app_path_var.get().strip()
        raw_args = self.custom_app_args_var.get().strip()

        if not exe or not os.path.isfile(exe):
            messagebox.showerror("Error", f"Application not found:\n{exe or '(empty path)'}")
            return

        socks = self._get_socks_addr()
        socks_url = f"socks5://{socks}"

        raw_args = raw_args.replace("{socks}", socks)
        args = [exe] + self._split_cmdline(raw_args)

        try:
            subprocess.Popen(
                args,
                cwd=os.path.dirname(exe) or None,
                env=self._build_proxy_env(socks_url),
            )
            self._append_log(
                f"[INFO] Started app via SOCKS {socks}\n"
                f"[INFO] EXE: {exe}\n"
                f"[INFO] ARGS: {' '.join(args[1:]) if len(args) > 1 else '(none)'}\n"
            )
        except Exception as e:
            messagebox.showerror("Launch error", str(e))
            self._append_log(f"[ERROR] Failed to start custom app: {e}\n")

    # -----------------------------
    # UI
    # -----------------------------
    def _build_ui(self):
        root = tk.Frame(self, bg=self.BG)
        root.pack(fill="both", expand=True)

        self._build_title_bar(root)

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab 1: Main
        tab_main = ttk.Frame(notebook, padding=10)
        notebook.add(tab_main, text="Main")

        ttk.Label(tab_main, text="VPN client exe:").grid(row=0, column=0, sticky="w", pady=(0, 10))
        ttk.Entry(tab_main, textvariable=self.exe_path, width=60).grid(row=0, column=1, sticky="we", padx=6, pady=(0, 10))
        ttk.Button(tab_main, text="Browse…", command=self._browse_exe).grid(row=0, column=2, pady=(0, 10))

        ttk.Label(tab_main, text="Config TOML:").grid(row=1, column=0, sticky="w", pady=(0, 10))
        ttk.Entry(tab_main, textvariable=self.cfg_path, width=60).grid(row=1, column=1, sticky="we", padx=6, pady=(0, 10))
        ttk.Button(tab_main, text="Browse…", command=self._browse_cfg).grid(row=1, column=2, pady=(0, 10))

        btns1 = ttk.Frame(tab_main)
        btns1.grid(row=2, column=0, columnspan=3, pady=10, sticky="we")

        controls_row = ttk.Frame(btns1)
        controls_row.pack(fill="x")

        browsers_row = ttk.Frame(btns1)
        browsers_row.pack(fill="x", pady=(8, 0))

        self.btn_start = ttk.Button(controls_row, text="Connect", command=self.start_vpn)
        self.btn_stop = ttk.Button(controls_row, text="Disconnect", command=self.stop_vpn, state="disabled")
        self.btn_clear = ttk.Button(controls_row, text="Clear log", command=self._clear_log)
        self.btn_chrome = ttk.Button(browsers_row, text="Chrome via VPN", command=lambda: self.launch_browser_via_vpn("chrome"))
        self.btn_edge = ttk.Button(browsers_row, text="Edge via VPN", command=lambda: self.launch_browser_via_vpn("edge"))
        self.btn_firefox = ttk.Button(browsers_row, text="Firefox via VPN", command=lambda: self.launch_browser_via_vpn("firefox"))
        self.btn_yandex = ttk.Button(browsers_row, text="Yandex via VPN", command=lambda: self.launch_browser_via_vpn("yandex"))
        self.btn_vscode = ttk.Button(browsers_row, text="VSCode via VPN", command=self.launch_vscode_via_vpn)

        self.btn_start.pack(side="left")
        self.btn_stop.pack(side="left", padx=8)
        self.btn_clear.pack(side="left", padx=8)
        self.btn_chrome.pack(side="left")
        self.btn_edge.pack(side="left", padx=8)
        self.btn_firefox.pack(side="left", padx=8)
        self.btn_yandex.pack(side="left", padx=8)
        self.btn_vscode.pack(side="left", padx=8)

        self.status = tk.StringVar(value="Status: disconnected")
        self.listener_status = tk.StringVar()
        status_frame = ttk.Frame(controls_row)
        status_frame.pack(side="right", anchor="e")
        ttk.Label(status_frame, textvariable=self.status).pack(anchor="e")
        ttk.Label(status_frame, textvariable=self.listener_status, foreground="#bdbdbd").pack(anchor="e")
        self._refresh_listener_status()

        self.log = tk.Text(
            tab_main,
            wrap="word",
            state="disabled",
            bg=self.BG,
            fg=self.LOG_FG,
            insertbackground="white",
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.BORDER,
        )
        self.log.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=10)

        app_launch_frame = ttk.LabelFrame(tab_main, text="Custom App via SOCKS", padding=10)
        app_launch_frame.grid(row=4, column=0, columnspan=3, sticky="we", pady=(0, 10))

        self.custom_app_path_var = tk.StringVar()
        self.custom_app_args_var = tk.StringVar()

        ttk.Label(app_launch_frame, text="Application EXE:").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(app_launch_frame, textvariable=self.custom_app_path_var, width=60).grid(
            row=0, column=1, sticky="we", padx=6, pady=4
        )
        ttk.Button(app_launch_frame, text="Browse…", command=self._browse_custom_app).grid(row=0, column=2, pady=4)

        ttk.Label(app_launch_frame, text="Arguments:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(app_launch_frame, textvariable=self.custom_app_args_var, width=60).grid(
            row=1, column=1, sticky="we", padx=6, pady=4
        )

        ttk.Label(
            app_launch_frame,
            text="Можно использовать {socks}, пример: --proxy-server=socks5://{socks}",
            foreground="#888"
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(4, 0))

        ttk.Label(
            app_launch_frame,
            text="Также прокидываются env: ALL_PROXY / HTTP_PROXY / HTTPS_PROXY",
            foreground="#888"
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(2, 0))

        ttk.Button(
            app_launch_frame,
            text="Launch App via SOCKS",
            command=self.launch_custom_app_via_vpn
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))

        app_launch_frame.columnconfigure(1, weight=1)

        tab_main.rowconfigure(3, weight=1)
        tab_main.columnconfigure(1, weight=1)

        # Tab 2: Configuration
        tab_config = ttk.Frame(notebook, padding=0)
        notebook.add(tab_config, text="Configuration")

        _, cfg = self._make_scrollable(tab_config)
        cfg.configure(padding=10)

        deeplink_frame = ttk.LabelFrame(cfg, text="Deep Link Import", padding=10)
        deeplink_frame.pack(fill="x", pady=5)

        self.deeplink_var = tk.StringVar(value=self.startup_deeplink or "")
        ttk.Label(deeplink_frame, text="TrustTunnel URI:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(deeplink_frame, textvariable=self.deeplink_var, width=60).grid(row=0, column=1, sticky="we", padx=5, pady=2)
        ttk.Button(deeplink_frame, text="Import", command=self.import_deeplink).grid(row=0, column=2, padx=5, pady=2)
        ttk.Label(
            deeplink_frame,
            text="Paste a tt://?... deep link to populate endpoint settings before connecting.",
            foreground="#888",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))
        deeplink_frame.columnconfigure(1, weight=1)

        # Endpoint
        endpoint_frame = ttk.LabelFrame(cfg, text="Endpoint Settings", padding=10)
        endpoint_frame.pack(fill="x", pady=5)

        self.hostname_var = self._create_string_var("endpoint", "hostname", default="")
        ttk.Label(endpoint_frame, text="Hostname:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(endpoint_frame, textvariable=self.hostname_var, width=40).grid(row=0, column=1, sticky="we", padx=5, pady=2)

        self.addresses_var = tk.StringVar(value=", ".join(self._get_nested(self.config, "endpoint", "addresses", default=[])))

        def sync_addresses_var():
            self.addresses_var.set(", ".join(self._get_nested(self.config, "endpoint", "addresses", default=[])))

        def on_addresses_change(*_):
            self._set_nested(self.config, "endpoint", "addresses", self._split_list(self.addresses_var.get()))
            self._schedule_autosave()

        self.addresses_var.trace_add("write", on_addresses_change)

        ttk.Label(endpoint_frame, text="Addresses:").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Entry(endpoint_frame, textvariable=self.addresses_var, width=40).grid(row=1, column=1, sticky="we", padx=5, pady=2)
        ttk.Button(
            endpoint_frame,
            text="Edit",
            command=lambda: self._edit_list(
                "Edit Addresses",
                self._get_nested(self.config, "endpoint", "addresses", default=[]),
                on_saved=sync_addresses_var,
            ),
        ).grid(row=1, column=2, padx=5, pady=2)

        self.username_var = self._create_string_var("endpoint", "username", default="")
        ttk.Label(endpoint_frame, text="Username:").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Entry(endpoint_frame, textvariable=self.username_var).grid(row=2, column=1, sticky="we", padx=5, pady=2)

        self.password_var = self._create_string_var("endpoint", "password", default="")
        ttk.Label(endpoint_frame, text="Password:").grid(row=3, column=0, sticky="w", pady=2)
        pwd_entry = ttk.Entry(endpoint_frame, textvariable=self.password_var, show="*")
        pwd_entry.grid(row=3, column=1, sticky="we", padx=5, pady=2)
        ttk.Button(endpoint_frame, text="Show", command=lambda: self._toggle_password(pwd_entry)).grid(row=3, column=2, padx=5, pady=2)

        self.skip_verification_var = self._create_bool_var("endpoint", "skip_verification", default=False)
        ttk.Checkbutton(endpoint_frame, text="Skip Certificate Verification", variable=self.skip_verification_var).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=5
        )

        endpoint_frame.columnconfigure(1, weight=1)

        # DNS
        dns_frame = ttk.LabelFrame(cfg, text="DNS Settings", padding=10)
        dns_frame.pack(fill="x", pady=5)

        self.dns_upstreams_var = tk.StringVar(value=", ".join(self._get_nested(self.config, "dns_upstreams", default=[])))

        def sync_dns_var():
            self.dns_upstreams_var.set(", ".join(self._get_nested(self.config, "dns_upstreams", default=[])))

        def on_dns_change(*_):
            self.config["dns_upstreams"] = self._split_list(self.dns_upstreams_var.get())
            self._schedule_autosave()

        self.dns_upstreams_var.trace_add("write", on_dns_change)

        ttk.Label(dns_frame, text="DNS Upstreams:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(dns_frame, textvariable=self.dns_upstreams_var, width=40).grid(row=0, column=1, sticky="we", padx=5, pady=2)
        ttk.Button(
            dns_frame,
            text="Edit",
            command=lambda: self._edit_list(
                "Edit DNS Upstreams",
                self._get_nested(self.config, "dns_upstreams", default=[]),
                on_saved=sync_dns_var,
            ),
        ).grid(row=0, column=2, padx=5, pady=2)

        dns_frame.columnconfigure(1, weight=1)

        # Exclusions
        exclusions_frame = ttk.LabelFrame(cfg, text="Exclusions", padding=10)
        exclusions_frame.pack(fill="x", pady=5)

        self.exclusions_var = tk.StringVar(
            value=", ".join(self._get_nested(self.config, "exclusions", default=[]))
        )

        def sync_exclusions_var():
            self.exclusions_var.set(", ".join(self._get_nested(self.config, "exclusions", default=[])))

        def on_exclusions_change(*_):
            self.config["exclusions"] = self._split_list(self.exclusions_var.get())
            self._schedule_autosave()

        self.exclusions_var.trace_add("write", on_exclusions_change)

        ttk.Label(exclusions_frame, text="Domains:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(exclusions_frame, textvariable=self.exclusions_var, width=40).grid(
            row=0, column=1, sticky="we", padx=5, pady=2
        )
        ttk.Button(
            exclusions_frame,
            text="Edit",
            command=lambda: self._edit_list(
                "Edit Exclusions",
                self._get_nested(self.config, "exclusions", default=[]),
                on_saved=sync_exclusions_var,
            ),
        ).grid(row=0, column=2, padx=5, pady=2)

        ttk.Label(
            exclusions_frame,
            text="One domain per item, for example: youtube.com or *.youtube.com",
            foreground="#888"
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))

        exclusions_frame.columnconfigure(1, weight=1)

        # Connection
        conn_frame = ttk.LabelFrame(cfg, text="Connection Settings", padding=10)
        conn_frame.pack(fill="x", pady=5)

        self.vpn_mode_var = self._create_root_string_var("vpn_mode", default="general")
        ttk.Label(conn_frame, text="VPN Mode:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Combobox(conn_frame, textvariable=self.vpn_mode_var, values=["general", "selective"], state="readonly").grid(
            row=0, column=1, sticky="w", padx=5, pady=2
        )

        self.killswitch_var = self._create_root_bool_var("killswitch_enabled", default=True)
        ttk.Checkbutton(conn_frame, text="Kill Switch Enabled", variable=self.killswitch_var).grid(row=1, column=0, sticky="w", pady=2)

        self.upstream_protocol_var = tk.StringVar(value=self._get_nested(self.config, "endpoint", "upstream_protocol", default="http2"))

        def on_upstream_change(*_):
            self._set_nested(self.config, "endpoint", "upstream_protocol", self.upstream_protocol_var.get())
            self._schedule_autosave()

        self.upstream_protocol_var.trace_add("write", on_upstream_change)

        ttk.Label(conn_frame, text="Upstream Protocol:").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Combobox(conn_frame, textvariable=self.upstream_protocol_var, values=["http2", "http3"], state="readonly").grid(
            row=2, column=1, sticky="w", padx=5, pady=2
        )

        self.anti_dpi_var = self._create_bool_var("endpoint", "anti_dpi", default=False)
        ttk.Checkbutton(conn_frame, text="Enable Anti-DPI", variable=self.anti_dpi_var).grid(row=3, column=0, sticky="w", pady=2)

        conn_frame.columnconfigure(1, weight=1)

        # Listener
        listener_frame = ttk.LabelFrame(cfg, text="Listener Settings", padding=10)
        listener_frame.pack(fill="x", pady=5)

        initial_listener_mode = self._detect_listener_mode_from_config()
        self.listener_mode_var = tk.StringVar(value=initial_listener_mode)

        ttk.Label(listener_frame, text="Listener Type:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Combobox(
            listener_frame,
            textvariable=self.listener_mode_var,
            values=["tun", "socks"],
            state="readonly",
            width=10,
        ).grid(row=0, column=1, sticky="w", padx=5, pady=2)

        # TUN frame
        self.tun_frame = ttk.LabelFrame(cfg, text="TUN Interface Settings", padding=10)

        self.included_routes_var = tk.StringVar(value=", ".join(self._get_nested(self.config, "listener", "tun", "included_routes", default=[])))
        self.excluded_routes_var = tk.StringVar(value=", ".join(self._get_nested(self.config, "listener", "tun", "excluded_routes", default=[])))

        def sync_included_routes_var():
            self.included_routes_var.set(", ".join(self._get_nested(self.config, "listener", "tun", "included_routes", default=[])))

        def sync_excluded_routes_var():
            self.excluded_routes_var.set(", ".join(self._get_nested(self.config, "listener", "tun", "excluded_routes", default=[])))

        def on_included_routes_change(*_):
            self._set_nested(self.config, "listener", "tun", "included_routes", self._split_list(self.included_routes_var.get()))
            self._schedule_autosave()

        def on_excluded_routes_change(*_):
            self._set_nested(self.config, "listener", "tun", "excluded_routes", self._split_list(self.excluded_routes_var.get()))
            self._schedule_autosave()

        self.included_routes_var.trace_add("write", on_included_routes_change)
        self.excluded_routes_var.trace_add("write", on_excluded_routes_change)

        ttk.Label(self.tun_frame, text="Included Routes:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(self.tun_frame, textvariable=self.included_routes_var, width=40).grid(row=0, column=1, sticky="we", padx=5, pady=2)
        ttk.Button(
            self.tun_frame,
            text="Edit",
            command=lambda: self._edit_list(
                "Edit Included Routes",
                self._get_nested(self.config, "listener", "tun", "included_routes", default=[]),
                on_saved=sync_included_routes_var,
            ),
        ).grid(row=0, column=2, padx=5, pady=2)

        ttk.Label(self.tun_frame, text="Excluded Routes:").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Entry(self.tun_frame, textvariable=self.excluded_routes_var, width=40).grid(row=1, column=1, sticky="we", padx=5, pady=2)
        ttk.Button(
            self.tun_frame,
            text="Edit",
            command=lambda: self._edit_list(
                "Edit Excluded Routes",
                self._get_nested(self.config, "listener", "tun", "excluded_routes", default=[]),
                on_saved=sync_excluded_routes_var,
            ),
        ).grid(row=1, column=2, padx=5, pady=2)

        self.mtu_var = self._create_int_var("listener", "tun", "mtu_size", default=1280)
        ttk.Label(self.tun_frame, text="MTU Size:").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Entry(self.tun_frame, textvariable=self.mtu_var, width=10).grid(row=2, column=1, sticky="w", padx=5, pady=2)

        self.change_dns_var = self._create_bool_var("listener", "tun", "change_system_dns", default=True)
        ttk.Checkbutton(self.tun_frame, text="Change System DNS", variable=self.change_dns_var).grid(row=3, column=0, sticky="w", pady=2)

        self.tun_frame.columnconfigure(1, weight=1)

        # SOCKS frame
        self.socks_frame = ttk.LabelFrame(cfg, text="SOCKS Listener Settings", padding=10)

        self.socks_address_var = self._create_string_var("listener", "socks", "address", default="127.0.0.1:1080")
        self.socks_user_var = self._create_string_var("listener", "socks", "username", default="")
        self.socks_pass_var = self._create_string_var("listener", "socks", "password", default="")

        ttk.Label(self.socks_frame, text="Address:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(self.socks_frame, textvariable=self.socks_address_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(self.socks_frame, text="Username:").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Entry(self.socks_frame, textvariable=self.socks_user_var, width=30).grid(row=1, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(self.socks_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=2)
        socks_pwd_entry = ttk.Entry(self.socks_frame, textvariable=self.socks_pass_var, show="*")
        socks_pwd_entry.grid(row=2, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(self.socks_frame, text="Show", command=lambda: self._toggle_password(socks_pwd_entry)).grid(row=2, column=2, padx=5, pady=2)

        self.socks_frame.columnconfigure(1, weight=1)

        def apply_listener_mode(*_):
            mode = self.listener_mode_var.get()

            try:
                self.tun_frame.pack_forget()
            except Exception:
                pass
            try:
                self.socks_frame.pack_forget()
            except Exception:
                pass

            if mode == "socks":
                self.socks_frame.pack(fill="x", pady=5)
            else:
                self.tun_frame.pack(fill="x", pady=5)

            self._refresh_listener_status()
            self._schedule_autosave()

        self.listener_mode_var.trace_add("write", apply_listener_mode)
        apply_listener_mode()

        ttk.Label(
            cfg,
            text="Passwords are stored in Windows secure storage (DPAPI) for the current user.",
            foreground="#888"
        ).pack(pady=(10, 0))

        ttk.Label(
            cfg,
            text="Saved TOML omits passwords. The GUI injects them only into a temporary runtime config when starting VPN.",
            foreground="#888"
        ).pack(pady=(6, 0))

        ttk.Label(
            cfg,
            text="Important: custom EXE via SOCKS works only for apps that support proxy via args or environment variables.",
            foreground="#888"
        ).pack(pady=(6, 0))

    def _toggle_password(self, entry):
        entry["show"] = "" if str(entry["show"]) == "*" else "*"

    # -----------------------------
    # Browse
    # -----------------------------
    def _browse_exe(self):
        p = filedialog.askopenfilename(title="Select vpn client exe", filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if p:
            self.exe_path.set(p)
            self._refresh_ready_status()

    def _browse_cfg(self):
        p = filedialog.askopenfilename(title="Select config.toml", filetypes=[("TOML", "*.toml"), ("All files", "*.*")])
        if p:
            self.config_path = p
            self.cfg_path.set(p)
            self.load_config()
            self._refresh_ready_status()

    # -----------------------------
    # Log
    # -----------------------------
    def _append_log(self, text: str):
        if not hasattr(self, "log"):
            return
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # -----------------------------
    # Status
    # -----------------------------
    def _refresh_ready_status(self):
        exe = self.exe_path.get().strip()
        cfg = self.cfg_path.get().strip()
        running = bool(self.proc and self.proc.poll() is None)

        if os.path.isfile(exe) and os.path.isfile(cfg):
            if not running:
                self.status.set("Status: ready")
            self.btn_start.configure(state="disabled" if running else "normal")
            self.btn_stop.configure(state="normal" if running else "disabled")
        else:
            missing = []
            if not os.path.isfile(exe):
                missing.append("exe")
            if not os.path.isfile(cfg):
                missing.append("toml")
            self.status.set(f"Status: missing {', '.join(missing)}")
            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="disabled")

        self._refresh_listener_status()
        self._update_tray_status()

    # -----------------------------
    # VPN start/stop
    # -----------------------------
    def start_vpn(self):
        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("Info", "VPN already running.")
            return

        exe = self.exe_path.get().strip()
        cfg = self.cfg_path.get().strip()

        if not os.path.isfile(exe):
            messagebox.showerror("Error", f"Exe not found:\n{exe}")
            self._refresh_ready_status()
            return

        if not os.path.isfile(cfg):
            messagebox.showerror("Error", f"Config not found:\n{cfg}")
            self._refresh_ready_status()
            return

        endpoint_password = str(self._get_nested(self.config, "endpoint", "password", default="") or "").strip()
        if not endpoint_password:
            messagebox.showerror("Error", "Endpoint password is empty. Enter it in Configuration before connecting.")
            self._refresh_ready_status()
            return

        exe_dir = os.path.dirname(exe)

        try:
            self.save_config(silent=True)
            runtime_cfg = self._create_runtime_config()
            cmd = [exe, "-c", runtime_cfg]
            self._append_log(f"> Starting: {exe} -c <temporary runtime config>\n")
            self.stop_read.clear()

            creationflags = 0
            startupinfo = None
            if os.name == "nt":
                creationflags = subprocess.CREATE_NO_WINDOW
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            self.proc = subprocess.Popen(
                cmd,
                cwd=exe_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                creationflags=creationflags,
                startupinfo=startupinfo,
            )
        except Exception as e:
            self._cleanup_runtime_config()
            messagebox.showerror("Error", str(e))
            self._refresh_ready_status()
            return

        self.running_listener_mode = self._selected_listener_mode()
        self.status.set("Status: connecting/running")
        self._refresh_listener_status()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self._update_tray_status()

        self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self.reader_thread.start()

    def _read_output(self):
        try:
            if not self.proc or not self.proc.stdout:
                return
            for line in self.proc.stdout:
                if self.stop_read.is_set():
                    break
                self.after(0, self._append_log, line)
        except Exception:
            self.after(0, self._append_log, "\n[reader error]\n")
        finally:
            self.after(0, self._on_process_exit)

    def stop_vpn(self):
        if not self.proc or self.proc.poll() is not None:
            self._cleanup_runtime_config()
            self._append_log("[INFO] VPN not running.\n")
            self._refresh_ready_status()
            return

        self._append_log("> Stopping...\n")
        self.stop_read.set()

        try:
            self.proc.terminate()
        except Exception:
            pass

        self.after(1200, self._force_kill_if_needed)

    def _force_kill_if_needed(self):
        if self.proc and self.proc.poll() is None:
            self._append_log("[WARN] Terminate timeout, killing process...\n")
            try:
                self.proc.kill()
            except Exception:
                pass

    def _poll_process_exit(self):
        try:
            if self.proc and self.proc.poll() is not None:
                self._on_process_exit()
        finally:
            self.after(self.PROC_EXIT_POLL_MS, self._poll_process_exit)

    def _on_process_exit(self):
        if not self.proc:
            self._refresh_ready_status()
            return

        rc = self.proc.poll()
        if rc is None:
            return

        self._append_log(f"\n[INFO] Process exited with code {rc}\n")

        self.proc = None
        self.running_listener_mode = None
        self.stop_read.set()
        self._cleanup_runtime_config()

        self.status.set("Status: disconnected")
        self._refresh_listener_status()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self._update_tray_status()

    # -----------------------------
    # Close/Exit
    # -----------------------------
    def _on_close(self):
        if self.minimize_to_tray_on_close:
            self._minimize_to_tray()
        else:
            self._exit_app()

    def _exit_app(self):
        try:
            self.minimize_to_tray_on_close = False
            try:
                self.stop_vpn()
            except Exception:
                pass
        finally:
            try:
                if self.tray_icon:
                    self.tray_icon.stop()
            except Exception:
                pass
            self._cleanup_runtime_config()
            self.destroy()


if __name__ == "__main__":
    if not relaunch_as_admin_if_needed():
        sys.exit(0)
    app = VpnGui(startup_args=sys.argv[1:])
    app.mainloop()
