# 🔒 Steganography Tool

> Hide secret text or file contents inside PNG/BMP images using **LSB (Least Significant Bit)** steganography — with optional **AES-256 encryption**, an animated splash screen, and a sleek dark-themed GUI.

---

## ✨ Features

- 🖼️ Embed secret messages inside PNG / BMP images
- 🔐 Optional AES-256 encryption via password (PBKDF2 + Fernet)
- 📂 Load message from a text file or type directly
- 🖱️ Drag-and-drop image support
- 🔍 Extract & decrypt hidden messages from encoded images
- 🎬 Animated splash screen + smooth UI transitions
- 📋 Copy decoded message to clipboard or save to file
- 💻 Cross-platform: Windows & Linux

---

## 📁 Project Structure

```
stegano/
├── stegano_tool.py   # Main application (engine + GUI)
└── requirements.txt  # Python dependencies
```

---

## ⚙️ Requirements

| Package | Purpose | Required? |
|---|---|---|
| `Pillow` | Image read/write | ✅ Yes |
| `cryptography` | AES-256 encryption | ⚠️ Optional |
| `tkinterdnd2` | Drag-and-drop support | ⚠️ Optional |

> Without `cryptography`, messages are stored unencrypted.  
> Without `tkinterdnd2`, drag-and-drop is disabled — click-to-browse still works.

---

## 🐧 Installation — Linux

### 1. Clone or download the project

```bash
git clone https://github.com/dhanush-404/stegano.git
cd stegano
```

### 2. (Recommended) Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> On system-managed Python (e.g. Kali Linux), add `--break-system-packages`:
> ```bash
> pip install --break-system-packages -r requirements.txt
> ```

### 4. Install tkinter (if missing)

```bash
# Debian / Ubuntu / Kali
sudo apt install python3-tk

# Fedora
sudo dnf install python3-tkinter

# Arch
sudo pacman -S tk
```

### 5. Run the tool

```bash
python3 stegano_tool.py
```

---

## 🪟 Installation — Windows

### 1. Install Python 3.10+

Download from [python.org](https://www.python.org/downloads/).  
✅ Make sure to check **"Add Python to PATH"** during installation.

### 2. Clone or download the project

```cmd
git clone https://github.com/dhanush-404/stegano.git
cd stegano
```

Or download the ZIP and extract it.

### 3. (Recommended) Create a virtual environment

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 4. Install dependencies

```cmd
pip install -r requirements.txt
```

### 5. Run the tool

```cmd
python stegano_tool.py
```

Or double-click `stegano_tool.py` if `.py` files are associated with Python.

---

## 🚀 Usage Guide

### 🔒 Encoding (Hiding a Message)

1. Open the **Encode (Hide)** tab
2. Click the drop zone or drag a **PNG / BMP** image onto it
3. Choose **"Type message"** or **"Load from file"**
   - Type your secret message in the text box, OR
   - Click **Browse File** to load a `.txt` file
4. *(Optional)* Enter a **password** to encrypt the message with AES-256
5. Set the **output path** (defaults to `<original>_encoded.png`)
6. Click **🔒 ENCODE & SAVE**

> ✅ A success dialog confirms the output file and whether encryption was applied.

---

### 🔓 Decoding (Extracting a Message)

1. Open the **Decode (Extract)** tab
2. Click the drop zone or drag the **encoded PNG / BMP** image onto it
3. *(If encrypted)* Enter the **same password** used during encoding
4. Click **🔓 DECODE & EXTRACT**
5. The hidden message appears with a typewriter animation
6. Use **Copy to Clipboard** or **Save to File…** to export it

---

### 🛈 Notes

| ✅ Do | ❌ Don't |
|---|---|
| Use PNG or BMP images | Use JPEG — lossy compression destroys the hidden data |
| Save output as PNG | Re-encode the output image in a lossy format |
| Remember your password | Lose the password — recovery is impossible |
| Use larger images for longer messages | Exceed the image capacity (tool will warn you) |

---

## 📐 How LSB Steganography Works

Each pixel has 3 colour channels: **Red, Green, Blue** (0–255).  
The tool replaces the **least significant bit** of each channel with one bit of the hidden message.

```
Original : R = 1100 1010   G = 0111 0100   B = 1011 0011
Encoded  : R = 1100 1011   G = 0111 0100   B = 1011 0010
                     ↑                              ↑
               1 bit changed                  1 bit changed
```

The brightness shift is **±1 out of 256** — completely invisible to the human eye.

**Capacity formula:**

```
Max hidden bytes = (Width × Height × 3) / 8
```

Example: a 1920×1080 image can hold up to **~760 KB** of hidden data.

---

## 🔐 Encryption Details

When a password is provided:

- Key derivation: **PBKDF2-HMAC-SHA256**, 200,000 iterations
- Cipher: **Fernet** (AES-128-CBC + HMAC-SHA256)
- The encrypted payload is prefixed with `STGENC:` so the decoder knows to decrypt

---

## 👨‍💻 Developer

**Dhanush A**  
GitHub: [github.com/dhanush-404](https://github.com/dhanush-404)

---

## 📄 License

This project is open-source. Feel free to fork, modify, and use it.
