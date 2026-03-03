import os
import sys
import threading
import subprocess
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


def tray_log_error(prefix: str):
    try:
        log_path = os.path.join(get_app_dir(), "tray_error.log")
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
    return "[ " + ", ".join(parts) + " ]"  # NO trailing comma


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


if os.name == "nt" and not is_admin():
    try:
        import ctypes

        params = subprocess.list2cmdline(sys.argv)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", get_windows_gui_python_exe(), params, None, 1)
    except Exception:
        pass
    sys.exit(0)


# -----------------------------
# Main GUI
# -----------------------------
class VpnGui(tk.Tk):
    BG = "#1e1e1e"
    PANEL = "#1e1e1e"
    BTN_BG = "#2b2b2b"
    BTN_BG_HOVER = "#3c3c3c"
    FG = "#ffffff"
    LOG_FG = "#d4d4d4"
    BORDER = "#3c3c3c"

    AUTOSAVE_DEBOUNCE_MS = 700
    PROC_EXIT_POLL_MS = 300

    def __init__(self):
        super().__init__()

        self.overrideredirect(True)
        self.configure(bg=self.BG)

        self.title("TrustTunnel VPN")
        self.geometry("900x820")
        self.minsize(800, 500)

        self.proc: subprocess.Popen | None = None
        self.reader_thread: threading.Thread | None = None
        self.stop_read = threading.Event()

        self._drag_offset_x = 0
        self._drag_offset_y = 0

        self.tray_icon: pystray.Icon | None = None
        self.minimize_to_tray_on_close = True

        app_dir = get_app_dir()
        self.config_path = os.path.join(app_dir, "trusttunnel_client.toml")
        self.config: dict = {}
        self._autosave_job = None

        self.icon_path = os.path.join(app_dir, "icon.png")  # optional

        self.load_config()

        self.exe_path = tk.StringVar(value=os.path.join(app_dir, "trusttunnel_client.exe"))
        self.cfg_path = tk.StringVar(value=self.config_path)

        self._apply_dark_theme()
        self._build_ui()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._refresh_ready_status()

        self.after(300, self._ensure_tray)
        self.after(self.PROC_EXIT_POLL_MS, self._poll_process_exit)

    # -----------------------------
    # Dark theme
    # -----------------------------
    def _apply_dark_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background=self.BG, foreground=self.FG)
        style.configure("TFrame", background=self.BG)
        style.configure("TLabel", background=self.BG, foreground=self.FG)

        style.configure("TButton", background=self.BTN_BG, foreground=self.FG, borderwidth=1)
        style.map("TButton", background=[("active", self.BTN_BG_HOVER)])

        style.configure("TEntry", fieldbackground=self.BTN_BG, foreground=self.FG)

        style.configure("TCheckbutton", background=self.BG, foreground=self.FG)
        style.map("TCheckbutton", background=[("active", self.BG)])

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
            "exclusions": [],
            "dns_upstreams": ["tls://1.1.1.1", "tcp://8.8.8.8:53"],
            "endpoint": {
                "hostname": "Your hostname DNS",
                "addresses": ["Your IP:443"],
                "has_ipv6": True,
                "username": "Your login",
                "password": "Your password",
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
            else:
                self.config = self._default_config()
                self.save_config(silent=True)
        except Exception as e:
            messagebox.showerror("Config Error", f"Failed to load config:\n{str(e)}")
            self.config = self._default_config()

        # Ensure structures exist
        if "listener" not in self.config or not isinstance(self.config["listener"], dict):
            self.config["listener"] = {}
        self.config["listener"].setdefault("tun", self._default_config()["listener"]["tun"])
        self.config["listener"].setdefault("socks", self._default_config()["listener"]["socks"])

    def save_config(self, silent: bool = False):
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)

            effective = self._build_effective_config_for_save()
            extra = self._build_inactive_listener_comment_block()

            write_toml_no_trailing_commas(self.config_path, effective, extra_comment_block=extra)

            if not silent:
                self._append_log("[INFO] Configuration saved.\n")
        except Exception as e:
            messagebox.showerror("Config Error", f"Failed to save config:\n{str(e)}")
            if not silent:
                self._append_log(f"[ERROR] Config save failed: {e}\n")

    def _detect_listener_mode_from_config(self) -> str:
        listener = self.config.get("listener", {})
        if isinstance(listener, dict):
            has_socks = "socks" in listener and isinstance(listener.get("socks"), dict)
            has_tun = "tun" in listener and isinstance(listener.get("tun"), dict)
            if has_socks and not has_tun:
                return "socks"
        return "tun"

    def _build_effective_config_for_save(self) -> dict:
        # ВАЖНО: клиент ожидает только один listener (tun ИЛИ socks) как активный.
        # Поэтому сохраняем только выбранный режим, а второй — комментируем.
        mode_var = getattr(self, "listener_mode_var", None)
        listener_mode = mode_var.get() if mode_var else self._detect_listener_mode_from_config()

        out = dict(self.config)
        listener_out = {}
        listener_in = self.config.get("listener", {}) if isinstance(self.config.get("listener"), dict) else {}

        if listener_mode == "socks":
            listener_out["socks"] = dict(listener_in.get("socks", {}))
        else:
            listener_out["tun"] = dict(listener_in.get("tun", {}))

        out["listener"] = listener_out
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

    def _build_inactive_listener_comment_block(self) -> str:
        mode_var = getattr(self, "listener_mode_var", None)
        listener_mode = mode_var.get() if mode_var else self._detect_listener_mode_from_config()

        if listener_mode == "socks":
            tun = self._get_nested(self.config, "listener", "tun", default={})
            return self._make_commented_table_block("listener.tun", tun)
        else:
            socks = self._get_nested(self.config, "listener", "socks", default={})
            if not socks:
                socks = {"address": "127.0.0.1:1080", "username": "", "password": ""}
            return self._make_commented_table_block("listener.socks", socks)

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
    # Scrollable helper for Configuration tab
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

        # Mouse wheel (Windows/macOS/Linux)
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
            text="TrustTunnel VPN",
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
    # Tray (minimal)
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
                "TrustTunnel VPN",
                self._create_tray_image(connected=bool(self.proc and self.proc.poll() is None)),
                "TrustTunnel VPN",
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
                self.tray_icon.title = "TrustTunnel: connected" if connected else "TrustTunnel: disconnected"
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
    # Browser helpers (Chrome/Edge via SOCKS)
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

    def _get_socks_addr(self) -> str:
        addr = self._get_nested(self.config, "listener", "socks", "address", default="127.0.0.1:1080")
        addr = str(addr).strip()
        return addr if addr else "127.0.0.1:1080"

    def launch_browser_via_vpn(self, browser: str):
        """
        Запуск Chrome/Edge через VPN по SOCKS.
        ВАЖНО: TrustTunnel-клиент по спецификации использует либо TUN, либо SOCKS listener.
        Чтобы браузер реально шёл через SOCKS, нужно выбрать Listener Type = socks и подключиться.
        """
        # 1) убедимся, что VPN запущен
        if not (self.proc and self.proc.poll() is None):
            messagebox.showinfo("Info", "VPN is not running. Click Connect first.")
            return

        # 2) убедимся, что listener = socks (иначе SOCKS просто не поднят)
        mode = getattr(self, "listener_mode_var", None).get() if getattr(self, "listener_mode_var", None) else "tun"
        if mode != "socks":
            messagebox.showwarning(
                "SOCKS required",
                "To run browser via VPN by proxy, set Listener Type = socks and reconnect.\n\n"
                "TUN mode does not expose a local SOCKS proxy."
            )
            return

        exe = self._find_chrome() if browser == "chrome" else self._find_edge()
        if not exe:
            messagebox.showerror("Error", f"{browser} not found (not installed in default paths).")
            return

        socks = self._get_socks_addr()

        # отдельный профиль "VPN", чтобы не трогать основной профиль браузера
        profile_dir = os.path.join(get_app_dir(), "browser_profiles", browser)
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
        btns1.grid(row=2, column=0, columnspan=3, pady=10)
        self.btn_start = ttk.Button(btns1, text="Connect", command=self.start_vpn)
        self.btn_stop = ttk.Button(btns1, text="Disconnect", command=self.stop_vpn, state="disabled")
        self.btn_clear = ttk.Button(btns1, text="Clear log", command=self._clear_log)

        self.btn_start.pack(side="left")
        self.btn_stop.pack(side="left", padx=8)
        self.btn_clear.pack(side="left", padx=8)

        # NEW: browser launch buttons
        self.btn_chrome = ttk.Button(btns1, text="Chrome via VPN", command=lambda: self.launch_browser_via_vpn("chrome"))
        self.btn_edge = ttk.Button(btns1, text="Edge via VPN", command=lambda: self.launch_browser_via_vpn("edge"))
        self.btn_chrome.pack(side="left", padx=8)
        self.btn_edge.pack(side="left", padx=8)

        self.status = tk.StringVar(value="Status: disconnected")
        ttk.Label(btns1, textvariable=self.status).pack(side="right")

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
        tab_main.rowconfigure(3, weight=1)
        tab_main.columnconfigure(1, weight=1)

        # Tab 2: Configuration (SCROLLABLE)
        tab_config = ttk.Frame(notebook, padding=0)
        notebook.add(tab_config, text="Configuration")

        _, cfg = self._make_scrollable(tab_config)
        cfg.configure(padding=10)

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

        # Listener Settings
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

        # TUN frame (will be packed dynamically)
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

        # SOCKS frame (will be packed dynamically)
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

        # Show only one listener frame at a time
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

            self._schedule_autosave()

        self.listener_mode_var.trace_add("write", apply_listener_mode)
        apply_listener_mode()

        ttk.Label(cfg, text="Note: Username/password are stored in TOML as plain text.", foreground="#888").pack(pady=(10, 0))

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

        cmd = [exe, "-c", cfg]
        exe_dir = os.path.dirname(exe)

        try:
            self._append_log(f"> Starting: {' '.join(cmd)}\n")
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
            messagebox.showerror("Error", str(e))
            self._refresh_ready_status()
            return

        self.status.set("Status: connecting/running")
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
        self.stop_read.set()

        self.status.set("Status: disconnected")
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
            self.destroy()


if __name__ == "__main__":
    app = VpnGui()
    app.mainloop()