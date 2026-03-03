#!/usr/bin/env python3
"""
Steganography Tool
==================
Hide and extract secret text/file content inside PNG/BMP images
using Least Significant Bit (LSB) steganography.

Optional AES-256 encryption via the `cryptography` package.
Drag-and-drop support via `tkinterdnd2` (degrades gracefully).
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import base64
from PIL import Image, ImageTk

# ── Optional: encryption ──────────────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ── Optional: drag-and-drop ───────────────────────────────────────────────────
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════════
#  STEGANOGRAPHY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

_DELIMITER  = "⟪END⟫"          # UTF-8 end-of-message sentinel
_ENC_PREFIX = b"STGENC:"        # marks an encrypted payload
_KDF_SALT   = b"stegano_v1_kdf" # fixed salt for PBKDF2


def _derive_key(password: str) -> bytes:
    """Derive a 32-byte Fernet key from a plain-text password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=200_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _encrypt(plaintext: str, password: str) -> bytes:
    """Return encrypted bytes prefixed with _ENC_PREFIX."""
    key = _derive_key(password)
    token = Fernet(key).encrypt(plaintext.encode("utf-8"))
    return _ENC_PREFIX + token


def _decrypt(raw: bytes, password: str) -> str:
    """Decrypt bytes produced by _encrypt(); raises on bad password."""
    key = _derive_key(password)
    try:
        return Fernet(key).decrypt(raw[len(_ENC_PREFIX):]).decode("utf-8")
    except InvalidToken:
        raise ValueError("Wrong password or corrupted data.")


def _to_bits(data: bytes) -> str:
    return "".join(format(b, "08b") for b in data)


def _from_bits(bits: str) -> bytes:
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8))


def image_capacity(path: str) -> int:
    """Return max hidden-bytes for the given image (3 bits / pixel → bytes)."""
    w, h = Image.open(path).size
    return (w * h * 3) // 8


def encode_image(src: str, message: str, dest: str, password: str = "") -> None:
    """
    Embed *message* into *src* image and save to *dest* (PNG/BMP).

    If *password* is non-empty and cryptography is available the payload
    is AES-256 encrypted before embedding.

    Raises ValueError when the message is too large for the image.
    """
    img = Image.open(src).convert("RGB")
    pixels = list(img.getdata())

    # Build binary payload
    if password and CRYPTO_AVAILABLE:
        raw_payload: bytes = _encrypt(message, password)
    else:
        raw_payload = message.encode("utf-8")

    # Append sentinel so the decoder knows where the data ends
    delimiter_bytes = _DELIMITER.encode("utf-8")
    bits = _to_bits(raw_payload + delimiter_bytes)

    max_bits = len(pixels) * 3
    if len(bits) > max_bits:
        raise ValueError(
            f"Message too large: needs {len(bits)//8:,} bytes but image "
            f"can only hold {max_bits//8:,} bytes."
        )

    # Embed one bit per channel LSB
    new_pixels = []
    idx = 0
    for (r, g, b) in pixels:
        if idx < len(bits):
            r = (r & ~1) | int(bits[idx]); idx += 1
        if idx < len(bits):
            g = (g & ~1) | int(bits[idx]); idx += 1
        if idx < len(bits):
            b = (b & ~1) | int(bits[idx]); idx += 1
        new_pixels.append((r, g, b))

    out_img = Image.new("RGB", img.size)
    out_img.putdata(new_pixels)

    # Force lossless format
    ext = os.path.splitext(dest)[1].lower()
    if ext not in (".png", ".bmp"):
        dest += ".png"
    out_img.save(dest)


def decode_image(src: str, password: str = "") -> str:
    """
    Extract a hidden message from *src*.

    Raises ValueError when no message is found or password is wrong.
    """
    img = Image.open(src).convert("RGB")
    pixels = list(img.getdata())

    # Collect all LSBs
    bits = "".join(str(ch & 1) for px in pixels for ch in px)

    # Look for the delimiter in byte-aligned positions
    all_bytes = _from_bits(bits)
    sentinel  = _DELIMITER.encode("utf-8")
    sep_idx   = all_bytes.find(sentinel)

    if sep_idx == -1:
        raise ValueError("No hidden message found in this image.")

    raw_payload = all_bytes[:sep_idx]

    if raw_payload.startswith(_ENC_PREFIX):
        if not password:
            raise ValueError("Message is encrypted – please supply a password.")
        if not CRYPTO_AVAILABLE:
            raise RuntimeError(
                "Install the 'cryptography' package to decrypt messages."
            )
        return _decrypt(raw_payload, password)

    return raw_payload.decode("utf-8", errors="replace")


# ═══════════════════════════════════════════════════════════════════════════════
#  GUI — THEME CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

C_BG       = "#1a1a2e"
C_CARD     = "#16213e"
C_ACCENT   = "#0f3460"
C_RED      = "#e94560"
C_GREEN    = "#00e676"
C_TEXT     = "#e0e0f0"
C_MUTED    = "#7a8aaa"
C_ENTRY_BG = "#0d1b2a"
FONT_UI    = ("Segoe UI", 10)
FONT_BOLD  = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_MONO  = ("Consolas", 10)


# ═══════════════════════════════════════════════════════════════════════════════
#  GUI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

class SteganoApp:
    def __init__(self, root: tk.Misc) -> None:
        self.root = root
        self.root.title("Steganography Tool – LSB Image Hiding")
        self.root.geometry("980x720")
        self.root.minsize(820, 620)
        self.root.configure(bg=C_BG)

        # State variables
        self.enc_img_path = tk.StringVar()
        self.enc_out_path = tk.StringVar()
        self.dec_img_path = tk.StringVar()

        self._setup_ttk_styles()
        self._build_header()
        self._build_notebook()
        self._build_statusbar()
        self._build_overlay()          # must be last so it sits on top

        if DND_AVAILABLE:
            self._setup_dnd()

        # Initial tab stretch after first render
        self.root.after(50, self._stretch_tabs)

    # ── Overlay / transition helpers ─────────────────────────────────────────

    _SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _build_overlay(self) -> None:
        """Build a hidden full-screen overlay used during encode/decode."""
        self._ov = tk.Frame(self.root, bg="#05090f")
        card = tk.Frame(self._ov, bg=C_CARD,
                        highlightbackground=C_RED, highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center", width=360, height=190)

        self._ov_spinner = tk.Label(card, text="⠋", bg=C_CARD, fg=C_RED,
                                    font=("Consolas", 40, "bold"))
        self._ov_spinner.pack(pady=(22, 2))

        self._ov_msg_var = tk.StringVar()
        tk.Label(card, textvariable=self._ov_msg_var,
                 bg=C_CARD, fg=C_TEXT,
                 font=("Segoe UI", 12, "bold")).pack()

        self._ov_sub_var = tk.StringVar()
        tk.Label(card, textvariable=self._ov_sub_var,
                 bg=C_CARD, fg=C_MUTED,
                 font=("Segoe UI", 9)).pack(pady=(4, 0))

        self._ov_spin_job = None
        self._ov_visible  = False

    def _show_overlay(self, msg: str, sub: str = "") -> None:
        self._ov_msg_var.set(msg)
        self._ov_sub_var.set(sub)
        self._ov.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._ov_visible = True
        self._ov.lift()
        self._spin_step(0)
        self.root.update_idletasks()

    def _hide_overlay(self) -> None:
        if self._ov_spin_job:
            self.root.after_cancel(self._ov_spin_job)
            self._ov_spin_job = None
        self._ov.place_forget()
        self._ov_visible = False

    def _spin_step(self, idx: int) -> None:
        if not self._ov_visible:
            return
        self._ov_spinner.config(
            text=self._SPINNER_FRAMES[idx % len(self._SPINNER_FRAMES)])
        self._ov_spin_job = self.root.after(
            80, lambda: self._spin_step(idx + 1))

    def _flash_status(self, color: str, steps: int = 10) -> None:
        """Briefly tint the status bar background then return to normal."""
        self._sbar.config(bg=color)
        if steps > 0:
            self.root.after(55, lambda: self._flash_status(C_ACCENT, steps - 1))
        else:
            self._sbar.config(bg=C_ACCENT)

    def _reveal_decoded(self, text: str) -> None:
        """Typewriter animation for the decoded output box (≤400 chars animated)."""
        MAX_ANIMATED = 400
        animated = text[:MAX_ANIMATED]
        rest     = text[MAX_ANIMATED:]

        self.dec_out.config(state="normal")
        self.dec_out.delete("1.0", "end")
        self.dec_out.config(state="disabled")

        def _type(idx: int) -> None:
            self.dec_out.config(state="normal")
            self.dec_out.insert("end", animated[idx])
            self.dec_out.see("end")
            self.dec_out.config(state="disabled")
            if idx < len(animated) - 1:
                self.root.after(6, lambda: _type(idx + 1))
            elif rest:
                self.dec_out.config(state="normal")
                self.dec_out.insert("end", rest)
                self.dec_out.see("end")
                self.dec_out.config(state="disabled")

        if animated:
            _type(0)
        elif rest:
            self.dec_out.config(state="normal")
            self.dec_out.insert("end", rest)
            self.dec_out.config(state="disabled")

    # ── Theming ───────────────────────────────────────────────────────────────

    def _setup_ttk_styles(self) -> None:
        s = ttk.Style()
        s.theme_use("clam")

        s.configure("TNotebook", background=C_BG, borderwidth=0, tabmargins=[0, 0, 0, 0])
        s.configure("TNotebook.Tab", background=C_ACCENT, foreground=C_TEXT,
                    padding=[22, 9], font=FONT_BOLD, anchor="center")
        s.map("TNotebook.Tab",
              background=[("selected", C_RED), ("active", C_ACCENT), ("pressed", C_ACCENT)],
              foreground=[("selected", "#ffffff"), ("active", C_TEXT), ("pressed", C_TEXT)],
              padding=[("selected", [22, 9]), ("active", [22, 9]),
                       ("pressed", [22, 9]), ("!selected", [22, 9])])

        s.configure("TFrame",        background=C_BG)
        s.configure("TLabel",        background=C_BG, foreground=C_TEXT, font=FONT_UI)
        s.configure("Card.TLabel",   background=C_CARD, foreground=C_TEXT, font=FONT_UI)

        s.configure("Accent.TButton", background=C_RED, foreground="#fff",
                    font=FONT_BOLD, padding=[14, 8], borderwidth=0, relief="flat",
                    focusthickness=0, focuscolor=C_RED, anchor="center")
        s.map("Accent.TButton",
              background=[("focus", C_RED), ("pressed", "#ff6a85"),
                          ("active", "#ff2d55"), ("!disabled", C_RED)],
              foreground=[("focus", "#fff"), ("pressed", "#fff"),
                          ("active", "#fff")],
              relief=[("pressed", "flat"), ("focus", "flat"), ("active", "flat")])

        s.configure("Soft.TButton", background=C_ACCENT, foreground=C_TEXT,
                    font=FONT_UI, padding=[10, 6], borderwidth=0, relief="flat",
                    focusthickness=0, focuscolor=C_ACCENT, anchor="center")
        s.map("Soft.TButton",
              background=[("focus", C_ACCENT), ("pressed", "#2a6aaa"),
                          ("active", "#1f5a9a")],
              foreground=[("focus", C_TEXT), ("pressed", C_TEXT),
                          ("active", C_TEXT)],
              relief=[("pressed", "flat"), ("focus", "flat"), ("active", "flat")])

        s.configure("TEntry",
                    fieldbackground=C_ENTRY_BG, foreground=C_TEXT,
                    insertcolor=C_TEXT, borderwidth=1, relief="solid")
        s.configure("TCheckbutton", background=C_BG, foreground=C_TEXT,
                    font=FONT_UI, focuscolor=C_BG)
        s.map("TCheckbutton",
              background=[("active", C_BG), ("pressed", C_BG),
                          ("hover",  C_BG), ("focus",   C_BG)],
              foreground=[("active", C_RED), ("pressed", C_RED)],
              indicatorcolor=[("selected", C_RED), ("pressed", C_RED)])

        s.configure("TRadiobutton", background=C_BG, foreground=C_TEXT,
                    font=FONT_UI, focuscolor=C_BG)
        s.map("TRadiobutton",
              background=[("active", C_BG), ("pressed", C_BG),
                          ("hover",  C_BG), ("focus",   C_BG)],
              foreground=[("active", C_RED), ("pressed", C_RED)])

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        hdr = tk.Frame(self.root, bg=C_ACCENT, height=68)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text=" \uff20 Steganography Tool",
                 bg=C_ACCENT, fg=C_RED, font=FONT_TITLE).pack(side="left", padx=20)
        tk.Label(hdr, text="Hide secrets inside images with LSB encoding",
                 bg=C_ACCENT, fg=C_MUTED, font=FONT_UI).pack(side="left")

        # Crypto status badge
        ok = CRYPTO_AVAILABLE
        badge = tk.Label(hdr,
                         text=(" \u2714 Encryption ON" if ok else " \u2718 Install cryptography"),
                         bg=("#27ae60" if ok else "#c0392b"), fg="#fff",
                         font=("Segoe UI", 9, "bold"), padx=10, pady=4)
        badge.pack(side="right", padx=18, pady=16)

        # DnD badge
        if DND_AVAILABLE:
            tk.Label(hdr, text=" \u2194 DnD ON",
                     bg="#1a6e3a", fg="#fff",
                     font=("Segoe UI", 9, "bold"), padx=8, pady=4
                     ).pack(side="right", padx=4, pady=16)

    # ── Notebook ──────────────────────────────────────────────────────────────

    def _build_notebook(self) -> None:
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=0, pady=(0, 0))

        enc_tab   = tk.Frame(self.nb, bg=C_BG)
        dec_tab   = tk.Frame(self.nb, bg=C_BG)
        about_tab = tk.Frame(self.nb, bg=C_BG)

        self.nb.add(enc_tab,   text="  🔒  Encode (Hide)  ")
        self.nb.add(dec_tab,   text="  🔓  Decode (Extract)  ")
        self.nb.add(about_tab, text="  🛈  About  ")

        self._build_encode_tab(enc_tab)
        self._build_decode_tab(dec_tab)
        self._build_about_tab(about_tab)

        # Stretch tabs to fill full width on every resize
        self.nb.bind("<Configure>", self._stretch_tabs)

    def _stretch_tabs(self, event=None) -> None:
        """Dynamically widen each tab so they collectively span the full notebook width."""
        try:
            n = self.nb.index("end")
            if n < 1:
                return
            total = self.nb.winfo_width()
            tab_w = max(1, (total // n) - 44)
            ttk.Style().configure("TNotebook.Tab", width=tab_w, anchor="center")
        except Exception:
            pass

    # ── Encode Tab ────────────────────────────────────────────────────────────

    def _build_encode_tab(self, parent: tk.Frame) -> None:
        # Two-column layout
        left  = tk.Frame(parent, bg=C_BG)
        right = tk.Frame(parent, bg=C_BG)
        left.pack(side="left",  fill="both", expand=True, padx=(10, 5), pady=8)
        right.pack(side="right", fill="both", expand=True, padx=(5, 10), pady=8)

        # ── LEFT: image picker ────────────────────────────────────────────────
        self._heading(left, "\u25b6  Step 1 — Select Cover Image")

        self.enc_drop = self._drop_zone(
            left, "Drop PNG / BMP here\nor click to browse",
            self._browse_enc_image)
        self.enc_drop.pack(fill="x", padx=4, pady=4)

        self.enc_img_info = tk.Label(
            left, text="No image selected", bg=C_CARD,
            fg=C_MUTED, font=("Segoe UI", 9), anchor="w", padx=8, pady=4)
        self.enc_img_info.pack(fill="x", padx=4)

        self.enc_thumb = tk.Label(left, bg=C_BG)
        self.enc_thumb.pack(pady=4)

        self._heading(left, "Capacity")
        self.cap_lbl = tk.Label(left, text="—", bg=C_BG,
                                fg=C_MUTED, font=("Segoe UI", 9))
        self.cap_lbl.pack(anchor="w", padx=6)

        # ── RIGHT: message / options / encode ─────────────────────────────────
        self._heading(right, "\u25b6  Step 2 — Message to Hide")

        src_row = tk.Frame(right, bg=C_BG)
        src_row.pack(fill="x", padx=4, pady=2)
        self.msg_src = tk.StringVar(value="text")
        ttk.Radiobutton(src_row, text="Type message", variable=self.msg_src,
                        value="text", command=self._toggle_msg_src).pack(side="left", padx=6)
        ttk.Radiobutton(src_row, text="Load from file", variable=self.msg_src,
                        value="file", command=self._toggle_msg_src).pack(side="left", padx=6)

        # Text area
        self.msg_box = scrolledtext.ScrolledText(
            right, height=8, bg=C_ENTRY_BG, fg=C_TEXT,
            insertbackground=C_TEXT, font=FONT_MONO,
            relief="flat", wrap="word", borderwidth=2)
        self.msg_box.pack(fill="x", padx=4, pady=4)
        self.msg_box.insert("1.0", "Type your secret message here…")
        self.msg_box.bind("<FocusIn>", self._clear_placeholder)

        # File picker row (hidden initially)
        self.file_row = tk.Frame(right, bg=C_BG)
        self.file_path = tk.StringVar()
        ttk.Entry(self.file_row, textvariable=self.file_path).pack(
            side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(self.file_row, text="Browse File",
                   style="Soft.TButton", command=self._browse_hidden_file).pack(side="right")

        # Encryption
        self._heading(right, "\u25b6  Step 3 — Encryption (Optional)")
        pw_row = tk.Frame(right, bg=C_BG)
        pw_row.pack(fill="x", padx=4, pady=2)
        tk.Label(pw_row, text="Password:", bg=C_BG, fg=C_TEXT, font=FONT_UI).pack(side="left")
        self.enc_pw = ttk.Entry(pw_row, show="*", width=24)
        self.enc_pw.pack(side="left", padx=8)
        self.enc_show = tk.BooleanVar()
        ttk.Checkbutton(pw_row, text="Show",
                        variable=self.enc_show,
                        command=lambda: self._toggle_show(self.enc_pw, self.enc_show)
                        ).pack(side="left")
        if not CRYPTO_AVAILABLE:
            tk.Label(right,
                     text="  \u26a0  Install 'cryptography' to enable encryption",
                     bg=C_BG, fg="#e67e22", font=("Segoe UI", 8)
                     ).pack(anchor="w", padx=4)

        # Output path
        self._heading(right, "\u25b6  Step 4 — Output Image")
        out_row = tk.Frame(right, bg=C_BG)
        out_row.pack(fill="x", padx=4, pady=2)
        ttk.Entry(out_row, textvariable=self.enc_out_path).pack(
            side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Button(out_row, text="Save As…",
                   style="Soft.TButton", command=self._browse_out).pack(side="right")

        # Action
        tk.Frame(right, bg=C_BG, height=8).pack()
        self._enc_btn = ttk.Button(right, text="  \U0001F512  ENCODE & SAVE  ",
                                  style="Accent.TButton",
                                  command=self._do_encode)
        self._enc_btn.pack(pady=6, ipadx=12, ipady=5)

    # ── Decode Tab ────────────────────────────────────────────────────────────

    def _build_decode_tab(self, parent: tk.Frame) -> None:
        left  = tk.Frame(parent, bg=C_BG)
        right = tk.Frame(parent, bg=C_BG)
        left.pack(side="left",  fill="both", expand=True, padx=(10, 5), pady=8)
        right.pack(side="right", fill="both", expand=True, padx=(5, 10), pady=8)

        # ── LEFT ──────────────────────────────────────────────────────────────
        self._heading(left, "\u25b6  Step 1 — Select Encoded Image")

        self.dec_drop = self._drop_zone(
            left, "Drop encoded PNG / BMP here\nor click to browse",
            self._browse_dec_image)
        self.dec_drop.pack(fill="x", padx=4, pady=4)

        self.dec_img_info = tk.Label(
            left, text="No image selected", bg=C_CARD,
            fg=C_MUTED, font=("Segoe UI", 9), anchor="w", padx=8, pady=4)
        self.dec_img_info.pack(fill="x", padx=4)

        self.dec_thumb = tk.Label(left, bg=C_BG)
        self.dec_thumb.pack(pady=4)

        # ── RIGHT ─────────────────────────────────────────────────────────────
        self._heading(right, "\u25b6  Step 2 — Password (if encrypted)")
        pw_row = tk.Frame(right, bg=C_BG)
        pw_row.pack(fill="x", padx=4, pady=2)
        tk.Label(pw_row, text="Password:", bg=C_BG, fg=C_TEXT, font=FONT_UI).pack(side="left")
        self.dec_pw = ttk.Entry(pw_row, show="*", width=24)
        self.dec_pw.pack(side="left", padx=8)
        self.dec_show = tk.BooleanVar()
        ttk.Checkbutton(pw_row, text="Show",
                        variable=self.dec_show,
                        command=lambda: self._toggle_show(self.dec_pw, self.dec_show)
                        ).pack(side="left")

        self._dec_btn = ttk.Button(right, text="  \U0001F513  DECODE & EXTRACT  ",
                                  style="Accent.TButton",
                                  command=self._do_decode)
        self._dec_btn.pack(pady=10, ipadx=12, ipady=5)

        self._heading(right, "\u25b6  Step 3 — Extracted Message")
        self.dec_out = scrolledtext.ScrolledText(
            right, height=14,
            bg=C_ENTRY_BG, fg=C_GREEN,
            insertbackground=C_TEXT, font=FONT_MONO,
            relief="flat", state="disabled", wrap="word", borderwidth=2)
        self.dec_out.pack(fill="both", expand=True, padx=4, pady=4)

        btn_row = tk.Frame(right, bg=C_BG)
        btn_row.pack(fill="x", padx=4, pady=2)
        ttk.Button(btn_row, text="Copy to Clipboard",
                   style="Soft.TButton", command=self._copy_dec).pack(side="left", padx=3)
        ttk.Button(btn_row, text="Save to File…",
                   style="Soft.TButton", command=self._save_dec).pack(side="left", padx=3)

    # ── About Tab ─────────────────────────────────────────────────────────────

    def _build_about_tab(self, parent: tk.Frame) -> None:
        import webbrowser

        txt = scrolledtext.ScrolledText(
            parent, bg=C_ENTRY_BG, fg=C_MUTED,
            font=("Consolas", 10), relief="flat", wrap="word")
        txt.pack(fill="both", expand=True, padx=20, pady=20)
        txt.insert("1.0", ABOUT_TEXT)

        # Make the GitHub URL a clickable hyperlink
        url = "https://github.com/dhanush-404"
        start = "1.0"
        while True:
            pos = txt.search(url, start, stopindex="end")
            if not pos:
                break
            end = f"{pos}+{len(url)}c"
            txt.tag_add("link", pos, end)
            start = end

        txt.tag_config("link", foreground="#4a9eff",
                       underline=True, font=("Consolas", 10))
        txt.tag_bind("link", "<Button-1>",
                     lambda _: webbrowser.open(url))
        txt.tag_bind("link", "<Enter>",
                     lambda _: txt.config(cursor="hand2"))
        txt.tag_bind("link", "<Leave>",
                     lambda _: txt.config(cursor=""))
        txt.config(state="disabled")

    # ── Status bar ────────────────────────────────────────────────────────────

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self.root, bg=C_ACCENT)
        bar.pack(side="bottom", fill="x")

        self._status = tk.StringVar(value="")
        self._sbar = tk.Label(bar, textvariable=self._status,
                              bg=C_ACCENT, fg=C_MUTED,
                              font=("Segoe UI", 9), anchor="w", padx=12, pady=4)
        self._sbar.pack(side="left", fill="x", expand=True)

        tk.Label(bar, text="✦  Developed by  Dhanush A  ✦",
                 bg=C_ACCENT, fg=C_RED,
                 font=("Palatino Linotype", 12, "italic bold"),
                 padx=18, pady=6).pack(side="right")

    # ── Widget helpers ────────────────────────────────────────────────────────

    def _heading(self, parent: tk.Frame, text: str) -> None:
        tk.Label(parent, text=text, bg=C_BG, fg=C_RED,
                 font=FONT_BOLD).pack(anchor="w", padx=6, pady=(10, 2))

    def _drop_zone(self, parent: tk.Frame, text: str, cmd) -> tk.Frame:
        """A clickable frame that acts as a drop zone."""
        frm = tk.Frame(parent, bg=C_CARD, height=82, cursor="hand2",
                       highlightbackground=C_ACCENT, highlightthickness=2)
        lbl = tk.Label(frm, text=text, bg=C_CARD, fg=C_MUTED,
                       font=FONT_UI, justify="center")
        lbl.pack(expand=True, pady=16)

        def _enter(_):
            frm.config(highlightbackground=C_RED)
            lbl.config(fg=C_RED)
        def _leave(_):
            frm.config(highlightbackground=C_ACCENT)
            lbl.config(fg=C_MUTED)

        for w in (frm, lbl):
            w.bind("<Button-1>", lambda _: cmd())
            w.bind("<Enter>",    _enter)
            w.bind("<Leave>",    _leave)
        return frm

    def _load_thumb(self, path: str, label: tk.Label) -> None:
        try:
            img = Image.open(path)
            img.thumbnail((210, 160))
            photo = ImageTk.PhotoImage(img)
            label.config(image=photo, text="")
            label.image = photo          # prevent GC
        except Exception:
            pass

    @staticmethod
    def _toggle_show(entry: ttk.Entry, var: tk.BooleanVar) -> None:
        entry.config(show="" if var.get() else "*")

    def _clear_placeholder(self, _event) -> None:
        if self.msg_box.get("1.0", "end-1c") == "Type your secret message here…":
            self.msg_box.delete("1.0", "end")

    def _status_set(self, msg: str) -> None:
        self._status.set(f"  {msg}")
        self.root.update_idletasks()

    # ── Drag-and-drop ─────────────────────────────────────────────────────────

    def _setup_dnd(self) -> None:
        try:
            self.enc_drop.drop_target_register(DND_FILES)
            self.enc_drop.dnd_bind("<<Drop>>", lambda e: self._set_enc_img(e.data.strip().strip("{}")))
            self.dec_drop.drop_target_register(DND_FILES)
            self.dec_drop.dnd_bind("<<Drop>>", lambda e: self._set_dec_img(e.data.strip().strip("{}")))
        except Exception:
            pass

    # ── Image setters ─────────────────────────────────────────────────────────

    def _set_enc_img(self, path: str) -> None:
        self.enc_img_path.set(path)
        try:
            cap  = image_capacity(path)
            img  = Image.open(path)
            w, h = img.size
            self.enc_img_info.config(
                text=f"  {os.path.basename(path)}   {w}×{h}   {img.format}",
                fg=C_GREEN)
            self.cap_lbl.config(
                text=f"Max hidden data: {cap:,} bytes  ≈  {cap // 1024} KB",
                fg=C_TEXT)
            base, _ = os.path.splitext(path)
            self.enc_out_path.set(base + "_encoded.png")
        except Exception as exc:
            self.enc_img_info.config(text=f"  Error: {exc}", fg=C_RED)
        self._load_thumb(path, self.enc_thumb)
        self._status_set(f"Cover image: {os.path.basename(path)}")

    def _set_dec_img(self, path: str) -> None:
        self.dec_img_path.set(path)
        try:
            img  = Image.open(path)
            w, h = img.size
            self.dec_img_info.config(
                text=f"  {os.path.basename(path)}   {w}×{h}   {img.format}",
                fg=C_GREEN)
        except Exception as exc:
            self.dec_img_info.config(text=f"  Error: {exc}", fg=C_RED)
        self._load_thumb(path, self.dec_thumb)
        self._status_set(f"Encoded image: {os.path.basename(path)}")

    # ── Browse callbacks ──────────────────────────────────────────────────────

    def _browse_enc_image(self) -> None:
        p = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[("Lossless images", "*.png *.bmp"),
                       ("PNG", "*.png"), ("BMP", "*.bmp")])
        if p:
            self._set_enc_img(p)

    def _browse_dec_image(self) -> None:
        p = filedialog.askopenfilename(
            title="Select Encoded Image",
            filetypes=[("Lossless images", "*.png *.bmp"),
                       ("PNG", "*.png"), ("BMP", "*.bmp")])
        if p:
            self._set_dec_img(p)

    def _browse_hidden_file(self) -> None:
        p = filedialog.askopenfilename(title="Select File to Hide")
        if p:
            self.file_path.set(p)

    def _browse_out(self) -> None:
        p = filedialog.asksaveasfilename(
            title="Save Encoded Image",
            defaultextension=".png",
            filetypes=[("PNG", "*.png"), ("BMP", "*.bmp")])
        if p:
            self.enc_out_path.set(p)

    def _toggle_msg_src(self) -> None:
        if self.msg_src.get() == "file":
            self.msg_box.pack_forget()
            self.file_row.pack(fill="x", padx=4, pady=4)
        else:
            self.file_row.pack_forget()
            self.msg_box.pack(fill="x", padx=4, pady=4)

    # ── Core actions ──────────────────────────────────────────────────────────

    def _do_encode(self) -> None:
        src = self.enc_img_path.get()
        dst = self.enc_out_path.get()
        pw  = self.enc_pw.get().strip()

        # ── Validate before showing overlay ──────────────────────────────────
        if not src:
            messagebox.showerror("Missing image", "Please select a cover image."); return
        if not dst:
            messagebox.showerror("Missing output", "Please specify an output path."); return

        if self.msg_src.get() == "text":
            msg = self.msg_box.get("1.0", "end-1c").strip()
            if not msg or msg == "Type your secret message here…":
                messagebox.showerror("Empty message", "Please type a message to hide."); return
        else:
            fp = self.file_path.get()
            if not fp:
                messagebox.showerror("No file", "Please select a file to embed."); return
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    msg = fh.read()
            except Exception as exc:
                messagebox.showerror("File error", str(exc)); return

        if pw and not CRYPTO_AVAILABLE:
            if not messagebox.askyesno(
                    "No crypto",
                    "The 'cryptography' package is not installed.\n"
                    "Message will be stored WITHOUT encryption.\nContinue?"):
                return
            pw = ""

        # ── Show overlay → run → reveal result ───────────────────────────────
        enc_label = "  \U0001F512  ENCODE & SAVE  "
        sub = f"{'Encrypting + ' if pw else ''}embedding into {os.path.basename(dst)}"
        self._show_overlay("Encoding…", sub)
        self._enc_btn.config(state="disabled")

        def _run() -> None:
            try:
                encode_image(src, msg, dst, pw)
                name = os.path.basename(dst)
                self._hide_overlay()
                self._status_set(f"Encoded successfully → {name}")
                self._flash_status("#1a6e3a")
                messagebox.showinfo(
                    "Success \u2714",
                    f"Message hidden successfully!\n\n"
                    f"Output : {dst}\n"
                    f"Encrypted : {'Yes \U0001F512' if pw else 'No'}")
            except Exception as exc:
                self._hide_overlay()
                self._status_set(f"Encoding failed: {exc}")
                self._flash_status("#7a1020")
                messagebox.showerror("Encode failed", str(exc))
            finally:
                self._enc_btn.config(state="normal", text=enc_label)

        self.root.after(80, _run)

    def _do_decode(self) -> None:
        src = self.dec_img_path.get()
        pw  = self.dec_pw.get().strip()

        if not src:
            messagebox.showerror("Missing image", "Please select an encoded image."); return

        dec_label = "  \U0001F513  DECODE & EXTRACT  "
        self._show_overlay("Decoding…", f"Scanning LSBs in {os.path.basename(src)}")
        self._dec_btn.config(state="disabled")

        def _run() -> None:
            try:
                msg = decode_image(src, pw)
                self._hide_overlay()
                self._status_set(f"Decoded successfully — {len(msg):,} characters extracted.")
                self._flash_status("#1a6e3a")
                self._reveal_decoded(msg)
            except Exception as exc:
                self._hide_overlay()
                self._status_set(f"Decode failed: {exc}")
                self._flash_status("#7a1020")
                messagebox.showerror("Decode failed", str(exc))
            finally:
                self._dec_btn.config(state="normal", text=dec_label)

        self.root.after(80, _run)

    def _copy_dec(self) -> None:
        txt = self.dec_out.get("1.0", "end-1c")
        if txt:
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)
            self._status_set("Copied to clipboard!")

    def _save_dec(self) -> None:
        txt = self.dec_out.get("1.0", "end-1c")
        if not txt:
            messagebox.showwarning("Nothing to save", "No decoded message to save."); return
        p = filedialog.asksaveasfilename(
            title="Save Decoded Message",
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")])
        if p:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(txt)
            self._status_set(f"Saved → {os.path.basename(p)}")


# ═══════════════════════════════════════════════════════════════════════════════
#  ABOUT TEXT
# ═══════════════════════════════════════════════════════════════════════════════

ABOUT_TEXT = """\
╔══════════════════════════════════════════════════════════════╗
║           STEGANOGRAPHY TOOL — LSB Image Hiding              ║
║        Python  ·  Pillow  ·  tkinter  ·  cryptography        ║
╚══════════════════════════════════════════════════════════════╝

WHAT IS STEGANOGRAPHY?
──────────────────────
Steganography hides the very existence of a secret, unlike
encryption which only scrambles it.  A casual observer sees
nothing unusual about the output image.

HOW LSB STEGANOGRAPHY WORKS
────────────────────────────
Each pixel has three 8-bit channels: Red, Green, Blue (0–255).
The Least Significant Bit (bit 0) of each channel is altered to
carry one bit of the hidden payload.

  Original pixel : R=11001010  G=01110100  B=10110011
  After encoding : R=11001011  G=01110100  B=10110010
                         ↑                       ↑
                    1 bit changed          1 bit changed

The brightness shift is at most ±1 out of 256 — completely
invisible to the human eye.

Capacity  =  (width × height × 3 channels) / 8  bytes

OPTIONAL ENCRYPTION
───────────────────
If the  cryptography  package is installed and a password is
supplied, the payload is encrypted with Fernet (AES-128-CBC +
HMAC-SHA256) before embedding.  The key is derived via PBKDF2
(SHA-256, 200 000 iterations) from the password.

This means even if someone extraction the hidden bytes, they
see only ciphertext — useless without the password.

SUPPORTED FORMATS
─────────────────
  ✓  PNG  — lossless compression; recommended
  ✓  BMP  — uncompressed; always safe
  ✗  JPEG — lossy compression destroys the LSBs; not supported

USAGE WORKFLOW
──────────────
  Encode:
    1. Select a PNG/BMP cover image
    2. Type your secret message (or load a text file)
    3. Optionally enter a password (requires 'cryptography')
    4. Choose where to save the output image
    5. Click ENCODE & SAVE

  Decode:
    1. Select the encoded PNG/BMP image
    2. Enter the password (if one was used during encoding)
    3. Click DECODE & EXTRACT
    4. Copy or save the revealed message

TIPS
────
• Larger images → more hidden capacity
• Use PNG output — JPEG re-encoding will destroy the hidden data
• Always note the password; without it, recovery is impossible

Built with Python 3 · Pillow · tkinter · cryptography · tkinterdnd2

──────────────────────────────────────────────────────────────────

  DEVELOPER
  ─────────
  Name    :  Dhanush A
  GitHub  :  https://github.com/dhanush-404
  Project :  Steganography Tool — LSB Image Hiding

  Feel free to fork, star, or contribute on GitHub!

──────────────────────────────────────────────────────────────────
"""


# ═══════════════════════════════════════════════════════════════════════════════
#  SPLASH SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class SplashScreen:
    """
    Animated intro screen shown before the main tool.

    Phases:
        1. Fade in the window
        2. Typewriter effect on "STEGANO"
        3. Typewriter effect on tagline
        4. Animated loading bar + status text
        5. Fade out → launch SteganoApp → fade back in
    """

    _TITLE     = "STEGANO"
    _TAGLINE   = "Hide secrets in plain sight"
    _BAR_W     = 380          # px width of loading bar
    _LOAD_STEPS = 50          # loading bar increments
    _LOAD_MS    = 38          # ms between bar steps
    _FADE_STEPS = 22          # alpha steps for fades
    _FADE_MS    = 16          # ms between fade steps
    _TYPE_TITLE_MS = 90       # ms between title letters
    _TYPE_TAG_MS   = 26       # ms between tagline letters

    # Colour palette (independent of global constants so splash stands alone)
    _C_BG    = "#050a14"
    _C_RED   = "#e94560"
    _C_TEXT  = "#e0e0f0"
    _C_MUTED = "#576a8a"
    _C_TRACK = "#111827"

    _STATUSES = [
        "Initializing engine",
        "Loading crypto module",
        "Preparing pixel canvas",
        "Building interface",
        "Applying theme",
        "Almost ready",
    ]

    def __init__(self, root: tk.Misc, on_done) -> None:
        self.root    = root
        self.on_done = on_done

        root.title("Stegano")
        root.geometry("980x720")
        root.minsize(820, 620)
        root.configure(bg=self._C_BG)
        root.attributes("-alpha", 0.0)   # start invisible

        self._build()
        # Kick off phase 1 after one draw cycle
        root.after(50, lambda: self._fade_in(0))

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.frame = tk.Frame(self.root, bg=self._C_BG)
        self.frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        # Vertical centring spacer
        tk.Frame(self.frame, bg=self._C_BG).pack(expand=True, fill="both")

        inner = tk.Frame(self.frame, bg=self._C_BG)
        inner.pack()

        # Large decorative icon
        tk.Label(inner, text="◈",
                 bg=self._C_BG, fg=self._C_RED,
                 font=("Segoe UI", 80, "bold")).pack()

        # Spacer
        tk.Frame(inner, bg=self._C_BG, height=6).pack()

        # Main title — filled in by typewriter
        self._title_var = tk.StringVar(value="")
        tk.Label(inner, textvariable=self._title_var,
                 bg=self._C_BG, fg=self._C_TEXT,
                 font=("Segoe UI", 54, "bold"),
                 width=9, anchor="center").pack()

        # Tagline — filled in by typewriter
        self._tag_var = tk.StringVar(value="")
        tk.Label(inner, textvariable=self._tag_var,
                 bg=self._C_BG, fg=self._C_MUTED,
                 font=("Segoe UI", 13), anchor="center").pack(pady=(4, 30))

        # Loading bar track
        track = tk.Frame(inner, bg=self._C_TRACK,
                         width=self._BAR_W, height=6)
        track.pack()
        track.pack_propagate(False)
        self._bar = tk.Frame(track, bg=self._C_RED, height=6)
        self._bar.place(x=0, y=0, width=0, height=6)

        # Animated status text below bar
        self._status_var = tk.StringVar(value="")
        tk.Label(inner, textvariable=self._status_var,
                 bg=self._C_BG, fg=self._C_MUTED,
                 font=("Consolas", 10)).pack(pady=(8, 0))

        # Bottom spacer
        tk.Frame(self.frame, bg=self._C_BG).pack(expand=True, fill="both")

        # Subtle version footer
        tk.Label(self.frame,
                 text="Python · Pillow · tkinter · LSB Steganography",
                 bg=self._C_BG, fg="#1e2d45",
                 font=("Segoe UI", 8)).pack(side="bottom", pady=8)

    # ── Phase helpers ─────────────────────────────────────────────────────────

    def _after(self, ms: int, fn) -> None:
        """Schedule *fn* only if the splash frame still exists."""
        def _safe():
            try:
                if self.frame.winfo_exists():
                    fn()
            except tk.TclError:
                pass
        self.root.after(ms, _safe)

    # Phase 1 — fade window in
    def _fade_in(self, step: int) -> None:
        self.root.attributes("-alpha", min(step / self._FADE_STEPS, 1.0))
        if step < self._FADE_STEPS:
            self._after(self._FADE_MS, lambda: self._fade_in(step + 1))
        else:
            self._after(120, lambda: self._type_title(0))

    # Phase 2 — typewriter for "STEGANO"
    def _type_title(self, idx: int) -> None:
        self._title_var.set(self._TITLE[: idx + 1])
        if idx < len(self._TITLE) - 1:
            self._after(self._TYPE_TITLE_MS, lambda: self._type_title(idx + 1))
        else:
            self._after(200, lambda: self._type_tag(0))

    # Phase 3 — typewriter for tagline
    def _type_tag(self, idx: int) -> None:
        self._tag_var.set(self._TAGLINE[: idx + 1])
        if idx < len(self._TAGLINE) - 1:
            self._after(self._TYPE_TAG_MS, lambda: self._type_tag(idx + 1))
        else:
            self._after(200, lambda: self._load_bar(0))

    # Phase 4 — animated loading bar
    def _load_bar(self, step: int) -> None:
        frac = step / self._LOAD_STEPS
        self._bar.place(width=int(self._BAR_W * frac))

        # Animated dots (cycling 0-3 dots every 5 steps)
        dots  = "." * (step // 5 % 4)
        label = self._STATUSES[min(
            int(frac * len(self._STATUSES)), len(self._STATUSES) - 1)]
        self._status_var.set(f"{label}{dots}")

        if step < self._LOAD_STEPS:
            self._after(self._LOAD_MS, lambda: self._load_bar(step + 1))
        else:
            self._status_var.set("Ready  ✔")
            self._after(480, lambda: self._fade_out(0))

    # Phase 5 — fade window out
    def _fade_out(self, step: int) -> None:
        self.root.attributes("-alpha",
                             max(1.0 - step / self._FADE_STEPS, 0.0))
        if step < self._FADE_STEPS:
            self._after(self._FADE_MS, lambda: self._fade_out(step + 1))
        else:
            self._transition()

    # Phase 6 — swap content, then fade back in
    def _transition(self) -> None:
        self.frame.destroy()
        self.root.configure(bg=C_BG)
        self.root.attributes("-alpha", 0.0)
        self.on_done()                           # build SteganoApp
        self._fade_in_main(0)

    def _fade_in_main(self, step: int) -> None:
        self.root.attributes("-alpha", min(step / self._FADE_STEPS, 1.0))
        if step < self._FADE_STEPS:
            self.root.after(self._FADE_MS,
                            lambda: self._fade_in_main(step + 1))


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    if DND_AVAILABLE:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()

    def launch_app() -> None:
        SteganoApp(root)

    SplashScreen(root, on_done=launch_app)
    root.mainloop()


if __name__ == "__main__":
    main()
