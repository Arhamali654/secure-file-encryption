"""
Secure File Encryption & Decryption System
==========================================
Author  : Arham
Stack   : Python 3.x | tkinter | cryptography | hashlib | os
Features: Random salt per file, Progress bar, File integrity (HMAC), Dark UI
"""

import os
import hashlib
import hmac
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64


# ─── Constants ────────────────────────────────────────────────────────────────

SALT_SIZE       = 16          # bytes  — random per file
ITERATIONS      = 100_000     # PBKDF2 iterations
HMAC_SIZE       = 32          # SHA-256 HMAC bytes appended to .enc file
CHUNK_SIZE      = 64 * 1024   # 64 KB chunks for progress tracking
DARK_BG         = "#0f0f0f"
PANEL_BG        = "#1a1a1a"
ACCENT          = "#00d4ff"
ACCENT2         = "#7b2fff"
TEXT_PRIMARY    = "#f0f0f0"
TEXT_MUTED      = "#888888"
SUCCESS         = "#00e676"
ERROR           = "#ff5252"
BTN_ENC         = "#00d4ff"
BTN_DEC         = "#7b2fff"
FONT_TITLE      = ("Courier New", 20, "bold")
FONT_LABEL      = ("Courier New", 10)
FONT_BTN        = ("Courier New", 11, "bold")
FONT_STATUS     = ("Courier New", 9)


# ─── Crypto Helpers ───────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet-compatible key from a password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 for integrity verification."""
    return hmac.new(key, data, hashlib.sha256).digest()


def encrypt_file(filepath: str, password: str, progress_cb) -> str:
    """
    Encrypt a file and save as <filename>.enc
    File format: [16 bytes salt][ciphertext][32 bytes HMAC]
    Returns path to .enc file.
    """
    salt = os.urandom(SALT_SIZE)
    key  = derive_key(password, salt)

    with open(filepath, "rb") as f:
        plaintext = f.read()

    total = len(plaintext)
    fernet = Fernet(key)

    # Simulate chunked progress for UX (Fernet encrypts all at once)
    progress_cb(30)
    ciphertext = fernet.encrypt(plaintext)
    progress_cb(70)

    mac = compute_hmac(key, ciphertext)
    out_path = filepath + ".enc"

    with open(out_path, "wb") as f:
        f.write(salt + ciphertext + mac)

    progress_cb(100)
    return out_path


def decrypt_file(filepath: str, password: str, progress_cb) -> str:
    """
    Decrypt a .enc file back to original.
    File format: [16 bytes salt][ciphertext][32 bytes HMAC]
    Returns path to decrypted file.
    """
    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) < SALT_SIZE + HMAC_SIZE:
        raise ValueError("File is too small or corrupted.")

    salt       = data[:SALT_SIZE]
    mac_stored = data[-HMAC_SIZE:]
    ciphertext = data[SALT_SIZE:-HMAC_SIZE]

    key = derive_key(password, salt)
    progress_cb(30)

    # Integrity check
    mac_computed = compute_hmac(key, ciphertext)
    if not hmac.compare_digest(mac_stored, mac_computed):
        raise ValueError("Integrity check failed — wrong password or file tampered.")

    progress_cb(60)
    fernet = Fernet(key)
    try:
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken:
        raise ValueError("Decryption failed — wrong password.")

    # Remove .enc extension
    if filepath.endswith(".enc"):
        out_path = filepath[:-4]
    else:
        out_path = filepath + ".decrypted"

    # Avoid overwriting existing file
    if os.path.exists(out_path):
        base, ext = os.path.splitext(out_path)
        out_path = f"{base}_decrypted{ext}"

    with open(out_path, "wb") as f:
        f.write(plaintext)

    progress_cb(100)
    return out_path


# ─── GUI ──────────────────────────────────────────────────────────────────────

class EncryptionApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SecureVault — File Encryption System")
        self.root.geometry("600x680")
        self.root.resizable(False, False)
        self.root.configure(bg=DARK_BG)

        self._build_ui()

    # ── UI Builder ─────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ──
        header = tk.Frame(self.root, bg=DARK_BG)
        header.pack(fill="x", padx=30, pady=(30, 10))

        tk.Label(
            header, text="🔐 SecureVault",
            font=FONT_TITLE, bg=DARK_BG, fg=ACCENT
        ).pack(anchor="w")

        tk.Label(
            header,
            text="AES-128 · Fernet · PBKDF2-SHA256 · HMAC Integrity",
            font=FONT_STATUS, bg=DARK_BG, fg=TEXT_MUTED
        ).pack(anchor="w", pady=(2, 0))

        self._divider()

        # ── File Selection ──
        self._section_label("📁  FILE SELECTION")
        file_frame = tk.Frame(self.root, bg=PANEL_BG, bd=0)
        file_frame.pack(fill="x", padx=30, pady=(0, 16))

        self.file_var = tk.StringVar(value="No file selected...")
        file_entry = tk.Entry(
            file_frame, textvariable=self.file_var,
            bg=PANEL_BG, fg=TEXT_MUTED, insertbackground=ACCENT,
            relief="flat", font=FONT_LABEL, bd=0
        )
        file_entry.pack(side="left", fill="x", expand=True, padx=(14, 0), ipady=10)

        browse_btn = tk.Button(
            file_frame, text="Browse",
            font=FONT_BTN, bg="#222222", fg=ACCENT,
            activebackground="#333", activeforeground=ACCENT,
            relief="flat", cursor="hand2",
            command=self._browse_file
        )
        browse_btn.pack(side="right", ipadx=16, ipady=8)
        self._hover(browse_btn, "#2a2a2a", "#222222")

        # ── Password ──
        self._section_label("🔑  PASSWORD")
        self._password_field("Password", "pass_var")
        self._password_field("Confirm Password", "confirm_var")

        # ── Buttons ──
        self._divider()
        btn_frame = tk.Frame(self.root, bg=DARK_BG)
        btn_frame.pack(fill="x", padx=30, pady=(8, 0))

        enc_btn = tk.Button(
            btn_frame, text="⬆  ENCRYPT",
            font=FONT_BTN, bg=BTN_ENC, fg=DARK_BG,
            activebackground="#00b8d9", activeforeground=DARK_BG,
            relief="flat", cursor="hand2",
            command=self._run_encrypt
        )
        enc_btn.pack(side="left", fill="x", expand=True, ipadx=10, ipady=14, padx=(0, 8))
        self._hover(enc_btn, "#00b8d9", BTN_ENC)

        dec_btn = tk.Button(
            btn_frame, text="⬇  DECRYPT",
            font=FONT_BTN, bg=BTN_DEC, fg=TEXT_PRIMARY,
            activebackground="#6a1fe0", activeforeground=TEXT_PRIMARY,
            relief="flat", cursor="hand2",
            command=self._run_decrypt
        )
        dec_btn.pack(side="right", fill="x", expand=True, ipadx=10, ipady=14, padx=(8, 0))
        self._hover(dec_btn, "#6a1fe0", BTN_DEC)

        # ── Progress Bar ──
        prog_frame = tk.Frame(self.root, bg=DARK_BG)
        prog_frame.pack(fill="x", padx=30, pady=(20, 0))

        tk.Label(
            prog_frame, text="PROGRESS",
            font=FONT_STATUS, bg=DARK_BG, fg=TEXT_MUTED
        ).pack(anchor="w")

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor=PANEL_BG,
            background=ACCENT,
            bordercolor=DARK_BG,
            lightcolor=ACCENT,
            darkcolor=ACCENT
        )

        self.progress = ttk.Progressbar(
            prog_frame, orient="horizontal",
            length=540, mode="determinate",
            style="Custom.Horizontal.TProgressbar"
        )
        self.progress.pack(fill="x", pady=(6, 0))

        # ── Status ──
        self._divider()
        self.status_var = tk.StringVar(value="Ready.")
        self.status_color = tk.StringVar(value=TEXT_MUTED)

        self.status_label = tk.Label(
            self.root, textvariable=self.status_var,
            font=FONT_STATUS, bg=DARK_BG, fg=TEXT_MUTED,
            wraplength=540, justify="left"
        )
        self.status_label.pack(anchor="w", padx=30)

        # ── Footer ──
        tk.Label(
            self.root,
            text="All encryption is performed offline · No data leaves your machine",
            font=("Courier New", 8), bg=DARK_BG, fg="#444444"
        ).pack(side="bottom", pady=14)

    def _section_label(self, text):
        tk.Label(
            self.root, text=text,
            font=("Courier New", 8, "bold"), bg=DARK_BG, fg=TEXT_MUTED
        ).pack(anchor="w", padx=30, pady=(0, 4))

    def _divider(self):
        tk.Frame(self.root, bg="#2a2a2a", height=1).pack(fill="x", padx=30, pady=12)

    def _password_field(self, label: str, var_attr: str):
        frame = tk.Frame(self.root, bg=PANEL_BG)
        frame.pack(fill="x", padx=30, pady=(0, 10))

        tk.Label(
            frame, text=label,
            font=FONT_LABEL, bg=PANEL_BG, fg=TEXT_MUTED, width=16, anchor="w"
        ).pack(side="left", padx=(14, 0))

        var = tk.StringVar()
        setattr(self, var_attr, var)

        entry = tk.Entry(
            frame, textvariable=var,
            show="●", bg=PANEL_BG, fg=TEXT_PRIMARY,
            insertbackground=ACCENT, relief="flat",
            font=FONT_LABEL, bd=0
        )
        entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(8, 0))

        # Eye toggle
        eye_var = tk.BooleanVar(value=False)

        def toggle(e=entry, v=eye_var):
            v.set(not v.get())
            e.config(show="" if v.get() else "●")
            eye_btn.config(text="🙈" if v.get() else "👁")

        eye_btn = tk.Button(
            frame, text="👁", font=("Segoe UI Emoji", 10),
            bg=PANEL_BG, fg=TEXT_MUTED,
            activebackground=PANEL_BG, relief="flat",
            cursor="hand2", command=toggle, bd=0
        )
        eye_btn.pack(side="right", padx=(0, 10))

    def _hover(self, widget, on_color, off_color):
        widget.bind("<Enter>", lambda e: widget.config(bg=on_color))
        widget.bind("<Leave>", lambda e: widget.config(bg=off_color))

    # ── Helpers ────────────────────────────────────────────────────────────

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.file_var.set(path)
            self._set_status(f"Selected: {os.path.basename(path)}", TEXT_MUTED)

    def _set_status(self, msg: str, color: str = TEXT_MUTED):
        self.status_var.set(msg)
        self.status_label.config(fg=color)

    def _set_progress(self, value: int):
        self.progress["value"] = value
        self.root.update_idletasks()

    def _validate(self, require_confirm=True) -> bool:
        if not self.file_var.get() or self.file_var.get() == "No file selected...":
            messagebox.showerror("Error", "Please select a file first.")
            return False
        if not os.path.isfile(self.file_var.get()):
            messagebox.showerror("Error", "Selected file does not exist.")
            return False
        pwd = self.pass_var.get()
        if len(pwd) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters.")
            return False
        if require_confirm and pwd != self.confirm_var.get():
            messagebox.showerror("Error", "Passwords do not match.")
            return False
        return True

    # ── Actions ────────────────────────────────────────────────────────────

    def _confirm_delete(self, filename: str) -> bool:
        """Ask user before deleting the original file."""
        return messagebox.askyesno(
            "Delete Original?",
            f"Encryption successful!\n\nDelete the original file?\n\n'{filename}'\n\n"
            "⚠️  This cannot be undone.",
            icon="warning"
        )

    def _run_encrypt(self):
        if not self._validate(require_confirm=True):
            return
        filepath = self.file_var.get()
        password = self.pass_var.get()
        self._set_progress(0)
        self._set_status("Encrypting...", ACCENT)

        def task():
            try:
                out = encrypt_file(filepath, password, self._set_progress)
                self._set_status(
                    f"✅  Encrypted successfully → {os.path.basename(out)}", SUCCESS
                )
                # Ask on main thread then delete
                if self.root.after(0, lambda: self._post_encrypt_delete(filepath)):
                    pass
            except Exception as ex:
                self._set_status(f"❌  Error: {ex}", ERROR)
                self._set_progress(0)

        threading.Thread(target=task, daemon=True).start()

    def _post_encrypt_delete(self, filepath: str):
        """Called on main thread after successful encryption."""
        if self._confirm_delete(os.path.basename(filepath)):
            try:
                os.remove(filepath)
                self._set_status(
                    f"✅  Encrypted & original deleted → {os.path.basename(filepath)}.enc",
                    SUCCESS
                )
                self.file_var.set("No file selected...")
            except Exception as ex:
                self._set_status(f"⚠️  Could not delete original: {ex}", ERROR)

    def _run_decrypt(self):
        if not self._validate(require_confirm=False):
            return
        filepath = self.file_var.get()
        password = self.pass_var.get()
        self._set_progress(0)
        self._set_status("Decrypting...", ACCENT2)

        def task():
            try:
                out = decrypt_file(filepath, password, self._set_progress)
                self._set_status(
                    f"✅  Decrypted successfully → {os.path.basename(out)}", SUCCESS
                )
                self.root.after(0, lambda: self._post_decrypt_delete(filepath))
            except Exception as ex:
                self._set_status(f"❌  Error: {ex}", ERROR)
                self._set_progress(0)

        threading.Thread(target=task, daemon=True).start()

    def _post_decrypt_delete(self, filepath: str):
        """Called on main thread after successful decryption."""
        if self._confirm_delete(os.path.basename(filepath)):
            try:
                os.remove(filepath)
                self._set_status(
                    f"✅  Decrypted & .enc file deleted → {os.path.basename(filepath)}",
                    SUCCESS
                )
                self.file_var.set("No file selected...")
            except Exception as ex:
                self._set_status(f"⚠️  Could not delete .enc file: {ex}", ERROR)


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
