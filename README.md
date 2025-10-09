# FileSeal

**FileSeal** is a lightweight desktop application that helps you ensure the **integrity of your files** over time.  
It can generate and verify hash files (like `.md5` or `.sha256`) for your folders, detect corrupted files,  
and optionally store all your hashes in a **SQLite database** for long-term integrity tracking.

It was originally built for personal media backups, but works with any type of file.  
The goal is to keep it **simple, fast, and reliable** — no installations, no dependencies, just run and check your files.

---

## Features


### Core Features
- **Generate file hashes** (`MD5`, `SHA-1`, `SHA-256`) to verify data integrity  
- **Work on entire folders**, including subfolders — no need to select files manually  
- **Handle multiple extensions at once** (`.mkv, .iso, .zip, ...`)  
- **Skip existing hash files** to save time during repeated runs  

### Verification
- **Verify existing `.md5`, `.sha1`, `.sha256` files** in a selected folder  
- **Detect missing or mismatched files** instantly  
- **Progress bar** and **real-time logs** for transparent feedback during operations  

### Database Integration (Optional)
- Use a **SQLite database** to store hashes permanently  
- **Update DB from hash files** automatically  
- **Compare current files with stored hashes** to detect corruption or modifications

### Configuration Persistence
- **Remembers your preferences** (extensions, algorithm, DB path)

---

## How It Works

### Hash Generation
Choose:
- A folder  
- One or more file extensions (`.mkv, .iso, ...`)  
- A hash algorithm (`md5`, `sha1`, or `sha256`)  

FileSeal will create a hash file next to each matching file.

Example:
```
Waterloo.1970.mkv
Waterloo.1970.mkv.md5
```

Each hash file contains:

```
MD5: a92dd1f581c979e8de9e024102d18a30  Waterloo.1970.mkv
```

---

### Verification
FileSeal scans for `.md5`, `.sha1`, or `.sha256` files:
- Checks if the original file still exists
- Recomputes its hash and compares it
- Displays results in the log

---

### Optional : Database Mode
For users who want to track file integrity over time or across multiple drives.

You can select or create a SQLite database to store hashes permanently.  
Once a DB is linked:
- **Update / Verify DB** → scan folder and update entries from existing hash files  
- **Verify with DB** → compare file hashes directly against those stored in the database  

Database structure:

| file_name | md5 | sha1 | sha256 |
|------------|-----|------|--------|


---

## Installation & Usage

### Option 1 — Windows Executable
If you just want to use the app:
1. Download the latest release from [Releases](../../releases)
2. Run `FileSeal.exe` (portable, no installation required)

### Option 2 — Run from Source
```bash
git clone https://github.com/<your-username>/FileSeal.git
cd FileSeal
pip install -r requirements.txt
python FileSeal.py
```

### Option 3 — Build Your Own Executable
```bash
py -m PyInstaller --onefile --noconsole --icon=FileSeal_icon.ico FileSeal.py
```

---

## Requirements

- Python 3.9+
- [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap)

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## Project Status

✔️ Stable and working