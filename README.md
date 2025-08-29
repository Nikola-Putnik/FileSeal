# FileSeal

Small desktop tool written in Java to generate and verify file hashes (`.md5`, `.sha256`, etc.).  
Mainly for checking file integrity after a backup or file transfer.

---

## Why?

Originally, I just needed a simple way to check that my files were still intact — especially for personal backups of movies and TV shows stored on external drives.

After a few disk issues, I started generating hashes for remuxed movies to verify their integrity over time.
At first, it was just for my own use, but I figured it could be helpful more broadly, and for any kind of file.

So I decided to turn it into a small desktop app: simple, flexible, and focused on doing one thing well.

---

## Status

Basic hash generation and verification are working.

---

## TODO

- [x] GUI window
- [x] Select folder and filter by extension
- [x] Generate `.md5` / `.sha256` files with custom format
- [x] Verify hash files
- [x] Scan subfolders recursively
- [x] Check if hash files already exists
- [ ] Progress status
- [ ] UI improvements
- [ ] Windows executable