import os
import sys
from pathlib import Path
import hashlib
import threading
import sqlite3
import configparser
import tkinter as tk
from tkinter import filedialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

__version__ = "1.0.2"

# -------------------------
# Utilities
# -------------------------

def compute_hash(filepath, algo):
    h = hashlib.new(algo)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_hashfile_line(line):
    # expected format: "ALGO: <hex>  <filename>"
    # Example: "MD5: a92d...  Waterloo.1970.mkv"
    line = line.strip()
    algo, rest = line.split(":", 1)
    algo = algo.lower()
    saved_hash, filename = rest.strip().split("  ")
    return algo, saved_hash, filename

# -------------------------
# App
# -------------------------

class FileSealApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"FileSeal v{__version__}")

        # State variables
        self.folder_path = ttk.StringVar()
        self.extension = ttk.StringVar(value=".mkv, .iso")
        self.hash_alg = ttk.StringVar(value="md5")
        self.stop_requested = False

        # DB (optional)
        self.db_path = ttk.StringVar(value="(None)")
        self.db_conn = None
        self.last_db = ""

        # Load FileSeal_config.ini if exists
        if getattr(sys, "frozen", False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(__file__)
        self.config_file = os.path.join(base_dir, "FileSeal_config.ini")
        self.config = configparser.ConfigParser()

        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
            if "Settings" in self.config:
                self.extension.set(self.config["Settings"].get("extensions", ".mkv, .iso"))
                self.hash_alg.set(self.config["Settings"].get("hash_alg", "md5"))
                self.last_db = self.config["Settings"].get("db_path", "")
        else:
            self.extension.set(".mkv, .iso")
            self.hash_alg.set("md5")

        # --- Zone dossier ---
        frame_folder = ttk.Labelframe(root, text="Folder selection", padding=10)
        frame_folder.pack(fill="x", padx=10, pady=5)

        ttk.Entry(frame_folder, textvariable=self.folder_path).pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.browse_btn = ttk.Button(frame_folder, text="Browse...", command=self.select_folder, bootstyle="secondary")
        self.browse_btn.pack(side="left")

        # --- Zone options ---
        frame_opts = ttk.Labelframe(root, text="Options", padding=10)
        frame_opts.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_opts, text="Hash algorithm:").pack(side="left", padx=(15, 0))
        ttk.Combobox(frame_opts, textvariable=self.hash_alg, values=["md5", "sha1", "sha256"], state="readonly",
                     width=8).pack(side="left", padx=5)

        ttk.Label(frame_opts, text="File extensions:").pack(side="left")
        ttk.Entry(frame_opts, textvariable=self.extension, width=8).pack(side="left", fill="x", expand=True, padx=5)

        # --- Zone DB ---
        frame_db = ttk.Labelframe(root, text="Database (optional)", padding=10)
        frame_db.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_db, textvariable=self.db_path).pack(side="left", fill="x", expand=True)
        self.db_select_btn = ttk.Button(frame_db, text="Open database...", command=self.select_db, bootstyle="secondary")
        self.db_select_btn.pack(side="left", padx=5)
        self.db_create_btn = ttk.Button(frame_db, text="Create new...", command=self.create_db, bootstyle="secondary")
        self.db_create_btn.pack(side="left")

        # --- Zone actions fichiers ---
        frame_actions = ttk.Labelframe(root, text="Hash files actions", padding=10)
        frame_actions.pack(fill="x", padx=10, pady=5)

        self.gen_btn = ttk.Button(frame_actions, text="Generate hash files", command=self.run_generate)
        self.gen_btn.pack(side="left", padx=5)
        self.ver_btn = ttk.Button(frame_actions, text="Verify hash files", command=self.run_verify)
        self.ver_btn.pack(side="left", padx=5)
        self.stop_btn = ttk.Button(frame_actions, text="⏹ Stop", command=self.request_stop, state="disabled", bootstyle="danger")
        self.stop_btn.pack(side="left", padx=5)

        # --- Zone actions DB ---
        frame_db_actions = ttk.Labelframe(root, text="Database actions", padding=10)
        frame_db_actions.pack(fill="x", padx=10, pady=5)

        self.db_update_btn = ttk.Button(frame_db_actions, text="Update database from hash files", command=self.run_db_update,
                                       state="disabled")
        self.db_update_btn.pack(side="left", padx=5)
        self.db_verify_btn = ttk.Button(frame_db_actions, text="Verify files against database", command=self.run_db_verify,
                                       state="disabled")
        self.db_verify_btn.pack(side="left", padx=5)

        # --- Zone de log ---
        self.log = ttk.Text(root, height=16, state="disabled")
        self.log.pack(fill="both", padx=10, pady=10)

        # Couleurs
        self.log.tag_config("green", foreground="green")
        self.log.tag_config("red", foreground="red")
        self.log.tag_config("blue", foreground="DodgerBlue4")

        # --- Progress bar ---
        self.progress = ttk.Progressbar(root, orient="horizontal", mode="determinate", bootstyle="primary")
        self.progress.pack(fill="x", padx=10, pady=(0,10))

        if self.last_db and os.path.exists(self.last_db):
            try:
                self.db_conn = sqlite3.connect(self.last_db, check_same_thread=False)
                self.init_db(self.db_conn)
                self.db_path.set(self.last_db)
                self.set_db_controls_state(enabled=True)
                self.log_msg(f"💾 Restored database: {self.last_db}", "blue")
            except Exception as e:
                self.log_msg(f"⚠️ Unable to reopen the database '{self.last_db}': {e}", "red")

        self.root.protocol("WM_DELETE_WINDOW", self.save_config_and_quit)

    # ------------- UI utils -------------
    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path.set(folder)

    def select_db(self):
        path = filedialog.askopenfilename(
            title="Select a SQLite database",
            filetypes=[("SQLite DB", "*.db"), ("All files", "*.*")]
        )
        if not path:
            return

        if self.db_conn:
            try:
                self.db_conn.close()
            except Exception:
                pass
            self.db_conn = None

        self.db_conn = sqlite3.connect(path, check_same_thread=False)
        self.init_db(self.db_conn)
        self.db_path.set(path)
        self.set_db_controls_state(enabled=True)
        self.log_msg(f"💾 Database opened: {path}", "blue")

    def create_db(self):
        path = filedialog.asksaveasfilename(
            title="Create a new SQLite database",
            defaultextension=".db",
            filetypes=[("SQLite DB", "*.db"), ("All files", "*.*")]
        )
        if not path:
            return

        if self.db_conn:
            try:
                self.db_conn.close()
            except Exception:
                pass
            self.db_conn = None

        self.db_conn = sqlite3.connect(path, check_same_thread=False)
        self.init_db(self.db_conn)
        self.db_path.set(path)
        self.set_db_controls_state(enabled=True)
        self.log_msg(f"💾 New database created: {path}", "blue")

    def init_db(self, conn):
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS files (
                filename TEXT PRIMARY KEY,
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT
            )
        """)
        conn.commit()

    def set_db_controls_state(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.db_update_btn.config(state=state)
        self.db_verify_btn.config(state=state)

    def clear_log(self):
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")

    def log_msg(self, msg, tag=None):
        self.log.config(state="normal")
        if tag:
            self.log.insert("end", msg + "\n", tag)
        else:
            self.log.insert("end", msg + "\n")
        self.log.config(state="disabled")
        self.log.see("end")

    def disable_controls(self):
        self.gen_btn.config(state="disabled")
        self.ver_btn.config(state="disabled")
        self.browse_btn.config(state="disabled")
        self.db_select_btn.config(state="disabled")
        self.db_create_btn.config(state="disabled")
        self.db_update_btn.config(state="disabled")
        self.db_verify_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

    def enable_controls(self):
        self.gen_btn.config(state="normal")
        self.ver_btn.config(state="normal")
        self.browse_btn.config(state="normal")
        self.db_select_btn.config(state="normal")
        self.db_create_btn.config(state="normal")
        # Reactivate the DB buttons only if a DB is selected
        if self.db_conn:
            self.db_update_btn.config(state="normal")
            self.db_verify_btn.config(state="normal")
        else:
            self.db_update_btn.config(state="disabled")
            self.db_verify_btn.config(state="disabled")
        self.stop_btn.config(state="disabled")

    def start_operation(self):
        self.stop_requested = False
        self.clear_log()
        self.progress["value"] = 0
        self.progress["maximum"] = 1
        self.disable_controls()

    def end_operation(self, msg, tag=None):
        self.log_msg(msg, tag)
        self.enable_controls()

    def request_stop(self):
        self.stop_requested = True
        self.log_msg("⏹️ Stop request received - stopping after current file analysis.", "blue")
    
    def save_config_and_quit(self):
        self.config["Settings"] = {
            "extensions": self.extension.get(),
            "hash_alg": self.hash_alg.get(),
            "db_path": self.db_path.get() if self.db_conn else ""
        }
        with open(self.config_file, "w") as f:
            self.config.write(f)
        
        if self.db_conn:
            try:
                self.db_conn.close()
            except Exception:
                pass

        self.root.destroy()

    # ------------- Threads wrappers -------------
    def run_generate(self):
        self.start_operation()
        threading.Thread(target=self.generate_hashes, daemon=True).start()

    def run_verify(self):
        self.start_operation()
        threading.Thread(target=self.verify_hashes, daemon=True).start()

    def run_db_update(self):
        if not self.db_conn:
            self.log_msg("❌ No database selected.", "red")
            return
        self.start_operation()
        threading.Thread(target=self.db_update_from_hashfiles, daemon=True).start()

    def run_db_verify(self):
        if not self.db_conn:
            self.log_msg("❌ No database selected.", "red")
            return
        self.start_operation()
        threading.Thread(target=self.verify_with_db, daemon=True).start()

    # ------------- File Operations -------------
    def generate_hashes(self):
        folder = self.folder_path.get()
        exts = [e.strip() for e in self.extension.get().split(",") if e.strip()]
        algo = self.hash_alg.get()

        if not folder or not exts:
            self.end_operation("❌ Error: select a folder and an extension.", "red")
            return

        # Collect files by subfolders
        files = []
        for root_dir, _, filenames in os.walk(folder):
            for f in filenames:
                if any(f.endswith(ext) for ext in exts):
                    files.append(os.path.join(root_dir, f))

        if not files:
            self.end_operation(f"ℹ️ No {exts} files found.")
            return

        self.log_msg("▶️ Generation started...", "blue")
        self.progress.config(bootstyle="primary")
        self.progress["maximum"] = len(files)
        self.progress["value"] = 0

        created, skipped = 0, 0
        for filepath in files:
            if self.stop_requested:
                self.end_operation("⏹️ Generation has been interrupted by the user.", "blue")
                return

            hashfile = filepath + f".{algo}"
            if os.path.exists(hashfile):
                skipped += 1
                self.log_msg(f"⏩ Already exists: {hashfile}")
            else:
                h = compute_hash(filepath, algo)
                with open(hashfile, "w", encoding="utf-8") as hf:
                    filename = os.path.basename(filepath)
                    hf.write(f"{algo.upper()}: {h}  {filename}\n")
                created += 1
                self.log_msg(f"✅ Created: {hashfile}")

            self.progress["value"] += 1
            self.root.update_idletasks()

        self.end_operation(f"✔️ Generation completed. Created: {created}, Ignored: {skipped}.", "green")

    def verify_hashes(self):
        folder = self.folder_path.get()
        if not folder:
            self.end_operation("❌ Error: select a folder.", "red")
            return

        # Recupere tous les hash files
        hashfiles = []
        for root_dir, _, filenames in os.walk(folder):
            for f in filenames:
                if f.endswith((".md5", ".sha1", ".sha256")):
                    hashfiles.append(os.path.join(root_dir, f))

        if not hashfiles:
            self.end_operation("ℹ️ No hash file found.")
            return

        self.log_msg("▶️ Verification started...", "blue")
        self.progress.config(bootstyle="primary")
        self.progress["maximum"] = len(hashfiles)
        self.progress["value"] = 0

        ok, corrupted, missing = 0, 0, 0
        for path in hashfiles:
            if self.stop_requested:
                self.end_operation("⏹️ Verification has been interrupted by the user.", "blue")
                return

            try:
                with open(path, "r", encoding="utf-8") as f:
                    line = f.readline().strip()
                algo, saved_hash, filename = parse_hashfile_line(line)
                orig_file = os.path.join(os.path.dirname(path), filename)
            except Exception:
                self.log_msg(f"⚠️ Invalid format: {path}")
                self.progress["value"] += 1
                self.root.update_idletasks()
                continue

            if not os.path.exists(orig_file):
                missing += 1
                self.log_msg(f"❌ Missing: {orig_file}", "red")
                self.progress.config(bootstyle="danger")
            else:
                current_hash = compute_hash(orig_file, algo)
                if current_hash != saved_hash:
                    corrupted += 1
                    self.log_msg(f"⚠️ Corrupted: {orig_file}", "red")
                    self.progress.config(bootstyle="danger")
                else:
                    ok += 1
                    self.log_msg(f"✅ OK: {orig_file}")

            self.progress["value"] += 1
            self.root.update_idletasks()

        if corrupted > 0 or missing > 0:
            self.end_operation(f"❌ Verification completed. OK: {ok}, Corrupted: {corrupted}, Missing: {missing}", "red")
        else:
            self.end_operation(f"✔️ Verification completed. All {ok} files are intact.", "green")

    # ------------- Operations DB -------------
    def db_update_from_hashfiles(self):
        """ "Scan .md5/.sha1/.sha256 files and synchronize the DB:
            - INSERT if filename is missing
            - UPDATE the algo column if NULL
            - Log conflict if the value differs
        """
        folder = self.folder_path.get()
        if not folder:
            self.end_operation("❌ Error: select a folder.", "red")
            return
        if not self.db_conn:
            self.end_operation("❌ No database selected.", "red")
            return

        # Liste des hash files
        hashfiles = []
        for root_dir, _, filenames in os.walk(folder):
            for f in filenames:
                if f.endswith((".md5", ".sha1", ".sha256")):
                    hashfiles.append(os.path.join(root_dir, f))

        if not hashfiles:
            self.end_operation("ℹ️ No hash file found.")
            return

        self.log_msg("▶️ Database update/verification (from hash files) has started...", "blue")
        self.progress.config(bootstyle="primary")
        self.progress["maximum"] = len(hashfiles)
        self.progress["value"] = 0

        c = self.db_conn.cursor()
        added, updated, conflicts, invalid = 0, 0, 0, 0

        for path in hashfiles:
            if self.stop_requested:
                self.end_operation("⏹️ Operation has been interrupted by the user.", "blue")
                return

            try:
                with open(path, "r") as f:
                    line = f.readline().strip()
                algo, saved_hash, filename = parse_hashfile_line(line)
            except Exception:
                invalid += 1
                self.log_msg(f"⚠️ Invalid format: {path}")
                self.progress["value"] += 1
                self.root.update_idletasks()
                continue

            # SELECT current row
            c.execute("SELECT md5, sha1, sha256 FROM files WHERE filename=?", (filename,))
            row = c.fetchone()

            if row is None:
                # Insert new
                c.execute(f"INSERT INTO files (filename, {algo}) VALUES (?, ?)", (filename, saved_hash))
                added += 1
                self.log_msg(f"🆕 Added to DB: {filename} ({algo})")
            else:
                idx = {"md5":0, "sha1":1, "sha256":2}[algo]
                current_val = row[idx]
                if current_val is None:
                    c.execute(f"UPDATE files SET {algo}=? WHERE filename=?", (saved_hash, filename))
                    updated += 1
                    self.log_msg(f"➕ Added {algo} hash to DB: {filename}")
                elif current_val != saved_hash:
                    conflicts += 1
                    self.log_msg(f"⚠️ DB conflict for {filename}: {algo} DB={current_val} vs fichier={saved_hash}", "red")
                else:
                    # already identical
                    self.log_msg(f"✅ DB ok for {filename} ({algo})")

            self.progress["value"] += 1
            self.root.update_idletasks()

        self.db_conn.commit()

        if conflicts > 0 or invalid > 0:
            self.end_operation(f"❌ Completed. Added: {added}, Updated: {updated}, Conflicts: {conflicts}, Invalid: {invalid}", "red")
        else:
            self.end_operation(f"✔️ Completed. Added: {added}, Updated: {updated}, Conflicts: {conflicts}, Invalid: {invalid}", "green")

    def verify_with_db(self):
        """ Recalculate file hashes (according to the chosen algorithm) and compare with the DB.
            - If filename missing in DB -> log
            - If algo column is NULL -> log
            - If hash differs -> log
            - Otherwise OK
        """
        folder = self.folder_path.get()
        exts = [e.strip() for e in self.extension.get().split(",") if e.strip()]
        algo = self.hash_alg.get()

        if not folder or not exts:
            self.end_operation("❌ Error: select a folder and an extension.", "red")
            return
        if not self.db_conn:
            self.end_operation("❌  No database selected.", "red")
            return

        # Collect files by extension
        files = []
        for root_dir, _, filenames in os.walk(folder):
            for f in filenames:
                if any(f.endswith(ext) for ext in exts):
                    files.append(os.path.join(root_dir, f))

        if not files:
            self.end_operation(f"ℹ️ No {exts} files found.")
            return

        self.log_msg(f"▶️ Verification with DB (hash: {algo}) started...", "blue")
        self.progress.config(bootstyle="primary")
        self.progress["maximum"] = len(files)
        self.progress["value"] = 0

        c = self.db_conn.cursor()
        ok, diff, missing_in_db, null_in_db = 0, 0, 0, 0

        for filepath in files:
            if self.stop_requested:
                self.end_operation("⏹️ Operation has been interrupted by the user.", "blue")
                return

            filename = os.path.basename(filepath)
            # Cherche dans DB
            c.execute(f"SELECT {algo} FROM files WHERE filename=?", (filename,))
            row = c.fetchone()
            if row is None:
                missing_in_db += 1
                self.log_msg(f"⚠️ Not in DB: {filename}")
            else:
                db_hash = row[0]
                if db_hash is None:
                    null_in_db += 1
                    self.log_msg(f"ℹ️ {algo} hash not found in DB for: {filename}")
                else:
                    current_hash = compute_hash(filepath, algo)
                    if current_hash != db_hash:
                        diff += 1
                        self.log_msg(f"⚠️ Mismatch (DB vs calculated): {filepath}", "red")
                    else:
                        ok += 1
                        self.log_msg(f"✅ OK (DB): {filepath}")

            self.progress["value"] += 1
            self.root.update_idletasks()

        if diff > 0 or missing_in_db > 0:
            self.end_operation(
                f"❌ Database verification completed. OK: {ok}, Mismatch: {diff}, Missing in DB: {missing_in_db}, Missing {algo} in DB: {null_in_db}",
                "red"
            )
        else:
            self.end_operation(
                f"✔️ Database verification completed. OK: {ok}, Missing {algo} in DB: {null_in_db}",
                "green"
            )

# -------------------------
# Main
# -------------------------

if __name__ == "__main__":
    root = ttk.Window(themename="cosmo") # dark mode: "darkly"

    style = ttk.Style()

    # Police par defaut
    style.configure(".", font=("Segoe UI", 10))

    # Boutons: padding uniforme
    style.configure("TButton", padding=6)

    # Labelframe: titres en gras
    style.configure("TLabelframe", font=("Segoe UI", 10, "bold"))
    style.configure("TLabelframe.Label", font=("Segoe UI", 10, "bold"))

    # Zone de texte (log)
    style.configure("TEntry", padding=4)

    app = FileSealApp(root)
    root.mainloop()