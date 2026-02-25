import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import traceback

import pystray
from PIL import Image, ImageDraw


# -----------------------------
# Helpers
# -----------------------------
def get_app_dir() -> str:
    # Folder where vpn_gui.exe lives (PyInstaller) or current .py
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def tray_log_error(prefix: str):
    # Write tray errors to a file next to the app
    try:
        log_path = os.path.join(get_app_dir(), "tray_error.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\n--- {prefix} ---\n")
            f.write(traceback.format_exc())
    except Exception:
        pass


# -----------------------------
# Auto-elevate (UAC)
# -----------------------------
def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


if os.name == "nt" and not is_admin():
    import ctypes
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
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

    def __init__(self):
        super().__init__()

        # Custom (dark) title bar
        self.overrideredirect(True)
        self.configure(bg=self.BG)

        self.title("VPN GUI Wrapper")
        self.geometry("900x600")
        self.minsize(700, 420)

        self.proc = None
        self.reader_thread = None
        self.stop_read = threading.Event()

        # Drag offsets
        self._drag_offset_x = 0
        self._drag_offset_y = 0

        # Tray
        self.tray_icon = None
        self.minimize_to_tray_on_close = True

        # Default paths from local app directory
        app_dir = get_app_dir()
        default_exe = os.path.join(app_dir, "trusttunnel_client.exe")
        default_cfg = os.path.join(app_dir, "trusttunnel_client.toml")

        self.exe_path = tk.StringVar(value=default_exe)
        self.cfg_path = tk.StringVar(value=default_cfg)

        self._apply_dark_theme()
        self._build_ui()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._refresh_ready_status()

        # Start tray after Tk fully starts
        self.after(300, self._ensure_tray)

    # -----------------------------
    # ttk dark theme
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

    # -----------------------------
    # Custom title bar
    # -----------------------------
    def _build_title_bar(self, parent):
        bar = tk.Frame(parent, bg=self.PANEL, highlightthickness=1, highlightbackground=self.BORDER)
        bar.pack(fill="x")

        title = tk.Label(
            bar,
            text="VPN GUI Wrapper",
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
        # Trick for overrideredirect window minimize
        self.overrideredirect(False)
        self.iconify()
        self.after(10, lambda: self.overrideredirect(True))

    # -----------------------------
    # Tray icon (robust)
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
                "VPN GUI Wrapper",
                self._create_tray_image(connected=bool(self.proc and self.proc.poll() is None)),
                "VPN GUI Wrapper",
                self._tray_menu(),
            )
            # IMPORTANT: non-blocking; best with Tkinter
            self.tray_icon.run_detached()
        except Exception:
            tray_log_error("TRAY START ERROR")

    def _update_tray_status(self):
        connected = bool(self.proc and self.proc.poll() is None)
        try:
            if self.tray_icon:
                self.tray_icon.icon = self._create_tray_image(connected=connected)
                self.tray_icon.title = "VPN: connected" if connected else "VPN: disconnected"
        except Exception:
            tray_log_error("TRAY UPDATE ERROR")

    def _minimize_to_tray(self):
        self._ensure_tray()
        self.withdraw()

    def _restore_from_tray(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    # -----------------------------
    # UI
    # -----------------------------
    def _build_ui(self):
        root = tk.Frame(self, bg=self.BG)
        root.pack(fill="both", expand=True)

        self._build_title_bar(root)

        content = ttk.Frame(root, padding=10)
        content.pack(fill="both", expand=True)

        top = ttk.Frame(content, padding=(0, 6, 0, 0))
        top.pack(fill="x")

        ttk.Label(top, text="VPN client exe:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.exe_path, width=80).grid(row=0, column=1, sticky="we", padx=6)
        ttk.Button(top, text="Browse…", command=self._browse_exe).grid(row=0, column=2)

        ttk.Label(top, text="Config TOML:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(top, textvariable=self.cfg_path, width=80).grid(row=1, column=1, sticky="we", padx=6, pady=(8, 0))
        ttk.Button(top, text="Browse…", command=self._browse_cfg).grid(row=1, column=2, pady=(8, 0))

        top.columnconfigure(1, weight=1)

        btns = ttk.Frame(content, padding=(0, 10, 0, 10))
        btns.pack(fill="x")

        self.btn_start = ttk.Button(btns, text="Connect", command=self.start_vpn)
        self.btn_stop = ttk.Button(btns, text="Disconnect", command=self.stop_vpn, state="disabled")
        self.btn_clear = ttk.Button(btns, text="Clear log", command=self._clear_log)

        self.btn_start.pack(side="left")
        self.btn_stop.pack(side="left", padx=8)
        self.btn_clear.pack(side="left", padx=8)

        self.status = tk.StringVar(value="Status: disconnected")
        ttk.Label(btns, textvariable=self.status).pack(side="right")

        mid = ttk.Frame(content)
        mid.pack(fill="both", expand=True)

        self.log = tk.Text(
            mid,
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
        self.log.pack(fill="both", expand=True)

    # -----------------------------
    # Browse
    # -----------------------------
    def _browse_exe(self):
        p = filedialog.askopenfilename(
            title="Select vpn client exe",
            filetypes=[("Executable", "*.exe"), ("All files", "*.*")]
        )
        if p:
            self.exe_path.set(p)
            self._refresh_ready_status()

    def _browse_cfg(self):
        p = filedialog.askopenfilename(
            title="Select config.toml",
            filetypes=[("TOML", "*.toml"), ("All files", "*.*")]
        )
        if p:
            self.cfg_path.set(p)
            self._refresh_ready_status()

    # -----------------------------
    # Log
    # -----------------------------
    def _append_log(self, text: str):
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
            for line in self.proc.stdout:
                if self.stop_read.is_set():
                    break
                self.after(0, self._append_log, line)
        except Exception:
            self.after(0, self._append_log, "\n[reader error]\n")
        finally:
            self.after(0, self._on_process_exit)

    def _on_process_exit(self):
        if self.proc:
            code = self.proc.poll()
            if code is not None:
                self._append_log(f"\n> Process exited with code {code}\n")

        self.proc = None
        self._refresh_ready_status()

    def stop_vpn(self):
        if not self.proc or self.proc.poll() is not None:
            return

        self._append_log("> Stopping...\n")
        self.stop_read.set()

        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._append_log("> Force kill...\n")
                self.proc.kill()
        except Exception as e:
            self._append_log(f"> Stop error: {e}\n")
        finally:
            self.proc = None
            self._refresh_ready_status()

    # -----------------------------
    # Exit / close
    # -----------------------------
    def _exit_app(self):
        if self.proc and self.proc.poll() is None:
            if not messagebox.askyesno("Exit", "VPN is still running. Stop and exit?"):
                return
            self.stop_vpn()

        try:
            if self.tray_icon:
                self.tray_icon.stop()
        except Exception:
            pass

        self.destroy()

    def _on_close(self):
        if self.minimize_to_tray_on_close:
            self._append_log("> Minimized to tray\n")
            self._minimize_to_tray()
            return
        self._exit_app()


if __name__ == "__main__":
    app = VpnGui()
    app.mainloop()