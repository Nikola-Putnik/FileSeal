# FileSeal

A small desktop app to generate and verify hash files for your personal files and backups.

I use it mainly for my own media backups, but it works with any type of file.  
The goal was to keep it lightweight, fast, and dead simple.

---

## Features

✅ Supports `MD5`, `SHA-1`, `SHA-256`  
✅ Works on entire folders (with subfolders)  
✅ Generates `.md5`, `.sha1`, or `.sha256` files next to the originals  
✅ Skips files that are already hashed  
✅ Verifies existing hash files  
✅ Progress bar and status logs  
✅ Clean and minimal interface (Java Swing)

---

## How it works

**Hash generation**  
You select a folder and a file type (`.mkv`, `.zip`, etc.), choose the hash algorithm, and FileSeal creates a `.md5` / `.sha256` file for each matching file.

Example:

```
Waterloo.1970.mkv
Waterloo.1970.mkv.md5
```

Each hash file contains:

```
MD5: a92dd1f581c979e8de9e024102d18a30  Waterloo.1970.mkv
```

**Hash verification**  
You point the app to a folder, and it scans for `.md5`, `.sha1`, etc.  
It checks if the original files are still there and if the hash still matches.

---

## Status

✔️ Working and stable  
I'm still adding small features and improving the interface a bit.