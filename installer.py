# The tkinter based installer code of Private Safe Messaging Client
# Copyright (C) 2025  bruh-moment-0

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.



import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import tempfile
import threading
import subprocess
import urllib.request
import os

GIT_URL = "https://github.com/git-for-windows/git/releases/download/v2.52.0.windows.1/Git-2.52.0-64-bit.exe"
CMAKE_URL = "https://github.com/Kitware/CMake/releases/download/v4.2.1/cmake-4.2.1-windows-x86_64.msi"
MSVC_URL = "https://aka.ms/vs/stable/vs_BuildTools.exe"

root: tk.Tk | None = None
status_var: tk.StringVar | None = None
step_var: tk.StringVar | None = None
progress: ttk.Progressbar | None = None
log_widget: ScrolledText | None = None
start_button: ttk.Button | None = None

def _set_status(text: str) -> None:
    if status_var is not None:
        status_var.set(text)

def _set_step(text: str) -> None:
    if step_var is not None:
        step_var.set(text)

def _set_progress(value: float) -> None:
    if progress is not None:
        progress["value"] = max(0, min(100, value))

def _append_log(text: str) -> None:
    if log_widget is None:
        return
    log_widget.configure(state="normal")
    log_widget.insert("end", text)
    log_widget.see("end")
    log_widget.configure(state="disabled")

def set_status(text: str) -> None:
    if root is not None:
        root.after(0, _set_status, text)

def set_step(text: str) -> None:
    if root is not None:
        root.after(0, _set_step, text)

def set_progress(value: float) -> None:
    if root is not None:
        root.after(0, _set_progress, value)

def append_log(text: str) -> None:
    if root is not None:
        root.after(0, _append_log, text)

def start_installation() -> None:
    if start_button is not None:
        start_button.config(state="disabled")
    set_status("Starting...")
    set_step("Preparing temporary folder")
    set_progress(0)
    t = threading.Thread(target=_run_installation, daemon=True)
    t.start()

def _run_installation() -> None:
    global start_button
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            _download_and_install_git(temp_dir)
            _download_and_install_cmake(temp_dir)
            _download_and_install_msvc(temp_dir)
        _install_pip_requirements()
        _ensure_liboqs_python()
        _test_oqs_import()
        set_progress(100)
        set_status("All components installed successfully.")
        set_step("Done.")

        if root is not None:
            root.after(0, lambda: messagebox.showinfo("Installation complete", "All components have been installed successfully.", parent=root)) # pyright: ignore[reportArgumentType]
    except Exception as exc:
        set_status("Installation failed.")
        set_step(str(exc))
        if root is not None:
            root.after(0, lambda: messagebox.showerror("Installation error", f"An error occurred during installation:\n\n{exc}", parent=root)) # pyright: ignore[reportArgumentType]
    finally:
        if root is not None and start_button is not None:
            root.after(0, lambda: start_button.config(state="normal")) # pyright: ignore[reportOptionalMemberAccess]

def _download_file(url: str, dest_path: str, label: str) -> None:
    set_status(f"{label} (downloading)")
    set_step(url)
    set_progress(0)
    append_log(f"\n[{label}] Downloading from {url}\n")
    def reporthook(block_num, block_size, total_size):
        if total_size <= 0:
            percent = 0
        else:
            downloaded = block_num * block_size
            percent = downloaded * 100.0 / total_size
        set_progress(percent)
    urllib.request.urlretrieve(url, dest_path, reporthook=reporthook)
    set_progress(100)
    append_log(f"[{label}] Download complete: {dest_path}\n")

def _run_silent(cmd, label: str) -> None:
    set_status(f"{label} (installing...)")
    set_step(" ".join(cmd))
    set_progress(0)
    append_log(f"\n--- {label} ---\n")
    append_log("Command: " + " ".join(cmd) + "\n")
    creationflags = (subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=creationflags)
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            append_log(line)
    finally:
        proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"{label} installer failed with exit code {proc.returncode}. Check the log output above for details.")
    set_progress(100)

def _download_and_install_git(temp_dir: str) -> None:
    label = "Git"
    if _is_git_installed():
        append_log(f"\n[{label}] Already installed. Skipping download/install.\n")
        set_status(f"{label} already installed (skipped).")
        set_progress(100)
        return
    git_path = os.path.join(temp_dir, "Git-Installer.exe")
    _download_file(GIT_URL, git_path, label)
    cmd = [git_path, "/VERYSILENT", "/NORESTART"]
    _run_silent(cmd, label)

def _download_and_install_cmake(temp_dir: str) -> None:
    label = "CMake"
    if _is_cmake_installed():
        append_log(f"\n[{label}] Already installed. Skipping download/install.\n")
        set_status(f"{label} already installed (skipped).")
        set_progress(100)
        return
    cmake_path = os.path.join(temp_dir, "cmake-installer.msi")
    _download_file(CMAKE_URL, cmake_path, label)
    cmd = ["msiexec", "/i", cmake_path, "/qn","/norestart"]
    _run_silent(cmd, label)

def _download_and_install_msvc(temp_dir: str) -> None:
    label = "MSVC Build Tools"
    if _is_msvc_installed():
        append_log(f"\n[{label}] Already installed. Skipping download/install.\n")
        set_status(f"{label} already installed (skipped).")
        set_progress(100)
        return
    vs_path = os.path.join(temp_dir, "vs_BuildTools.exe")
    _download_file(MSVC_URL, vs_path, label)
    cmd = [vs_path, "--quiet", "--wait", "--norestart", "--nocache", "--add", "Microsoft.VisualStudio.Workload.VCTools", "--includeRecommended"]
    _run_silent(cmd, label)

def _is_git_installed() -> bool:
    try:
        completed = subprocess.run(["git", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return completed.returncode == 0
    except FileNotFoundError:
        return False

def _is_cmake_installed() -> bool:
    try:
        completed = subprocess.run(["cmake", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return completed.returncode == 0
    except FileNotFoundError:
        return False

def _find_vswhere() -> str | None:
    candidates = []
    pf86 = os.environ.get("ProgramFiles(x86)")
    if pf86:
        candidates.append(os.path.join(pf86, "Microsoft Visual Studio", "Installer", "vswhere.exe"))
    pf = os.environ.get("ProgramFiles")
    if pf:
        candidates.append(os.path.join(pf, "Microsoft Visual Studio", "Installer", "vswhere.exe"))
    for path in candidates:
        if os.path.exists(path):
            return path
    return None

def _is_msvc_installed() -> bool:
    vswhere = _find_vswhere()
    if not vswhere:
        return False
    try:
        completed = subprocess.run(
            [vswhere, "-products", "*", "-requires", 
            
            "Microsoft.VisualStudio.Workload.VCTools", "-property", "installationPath"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return completed.returncode == 0 and bool(completed.stdout.strip())
    except Exception:
        return False

def _run_pip_command(cmd: list[str], label: str) -> None:
    set_status(f"{label}")
    set_step(" ".join(cmd))
    append_log(f"\n--- {label} ---\n")
    append_log("Command: " + " ".join(cmd) + "\n")
    creationflags = (subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=creationflags)
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            append_log(line)
    finally:
        proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"{label} failed with exit code {proc.returncode}. Check the log output above for details.")

def _install_pip_requirements() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    requirements_path = os.path.join(script_dir, "requirements.txt")
    if not os.path.exists(requirements_path):
        append_log(f"\n[Pip Requirements] requirements.txt not found at {requirements_path}. Skipping.\n")
        set_status("Pip requirements (skipped - file not found)")
        return
    append_log(f"\n[Pip Requirements] Found requirements.txt at {requirements_path}\n")
    cmd = ["pip", "install", "-r", requirements_path]
    _run_pip_command(cmd, "Installing pip requirements")

def _is_liboqs_python_installed() -> bool:
    try:
        completed = subprocess.run(["pip", "show", "oqs"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return completed.returncode == 0
    except Exception:
        return False

def _ensure_liboqs_python() -> None:
    if _is_liboqs_python_installed():
        append_log(f"\n[liboqs-python] Already installed. Skipping clone/install.\n")
        set_status("liboqs-python already installed (skipped)")
        return
    script_dir = os.path.dirname(os.path.abspath(__file__))
    liboqs_dir = os.path.join(script_dir, "liboqs-python")
    set_status("liboqs-python (cloning repository)")
    set_step("git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python")
    append_log(f"\n--- Cloning liboqs-python ---\n")
    append_log(f"Command: git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python\n")
    creationflags = (subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0)
    clone_cmd = ["git", "clone", "--depth", "1", "https://github.com/open-quantum-safe/liboqs-python"]
    clone_proc = subprocess.Popen(clone_cmd, cwd=script_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=creationflags)
    try:
        assert clone_proc.stdout is not None
        for line in clone_proc.stdout:
            append_log(line)
    finally:
        clone_proc.wait()
    if clone_proc.returncode != 0:
        raise RuntimeError(f"Failed to clone liboqs-python with exit code {clone_proc.returncode}. Check the log output above for details.")
    set_status("liboqs-python (installing)")
    set_step("pip install .")
    append_log(f"\n--- Installing liboqs-python ---\n")
    append_log(f"Command: pip install .\n")
    install_cmd = ["pip", "install", "."]
    install_proc = subprocess.Popen(install_cmd, cwd=liboqs_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=creationflags)
    try:
        assert install_proc.stdout is not None
        for line in install_proc.stdout:
            append_log(line)
    finally:
        install_proc.wait()
    if install_proc.returncode != 0:
        raise RuntimeError(f"Failed to install liboqs-python with exit code {install_proc.returncode}. Check the log output above for details.")

def _test_oqs_import() -> None:
    set_status("Testing oqs import")
    set_step("python -c \"import oqs\"")
    append_log(f"\n--- Testing oqs import ---\n")
    append_log("Command: python -c \"import oqs\"\n")
    creationflags = (subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0)
    cmd = ["python", "-c", "import oqs"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=creationflags)
    try:
        assert proc.stdout is not None
        output = proc.stdout.read()
        if output:
            append_log(output)
        else:
            append_log("Import successful (no output)\n")
    finally:
        proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to import oqs with exit code {proc.returncode}. Check the log output above for details.")
    append_log("oqs import test passed\n")

def build_ui() -> None:
    global root, status_var, step_var, progress, log_widget, start_button
    root = tk.Tk()
    root.title("PSM Setup")
    root.geometry("800x640")
    root.resizable(False, False)
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("Install.TButton", font=("Segoe UI", 10, "bold"), padding=6)
    style.configure("Main.TFrame", background="#1e1e1e")
    style.configure("Main.TLabel", background="#1e1e1e", foreground="#f3f3f3", font=("Segoe UI", 10))
    main = ttk.Frame(root, style="Main.TFrame", padding=16)
    main.pack(fill="both", expand=True)
    title = ttk.Label(main, text="Private Safe Messaging (PSM) Setup", style="Main.TLabel", font=("Segoe UI", 12, "bold"))
    title.pack(anchor="w", pady=(0, 8))
    desc = ttk.Label(main, text="Version: 1.1\n"
        "This program will download and install the required tools for PSM. This program does NOT install the source code of PSM.\n"
        "You can find the license of this setup program and PSM in 'license.txt' that comes with this setup program.\n"
        "Please keep this window open until the process finishes.", style="Main.TLabel", justify="left")
    desc.pack(anchor="w", pady=(0, 12))
    status_var = tk.StringVar(value="Ready to start.")
    step_var = tk.StringVar(value="Waiting...")
    progress = ttk.Progressbar(main, orient="horizontal", length=460, mode="determinate", maximum=100)
    progress.pack(fill="x", pady=(0, 6))
    status_label = ttk.Label(main, textvariable=status_var, style="Main.TLabel")
    status_label.pack(anchor="w")
    step_label = ttk.Label(main, textvariable=step_var, style="Main.TLabel", font=("Segoe UI", 9))
    step_label.pack(anchor="w", pady=(2, 8))
    log_label = ttk.Label(main, text="Details / Output:", style="Main.TLabel", font=("Segoe UI", 9, "bold"))
    log_label.pack(anchor="w")
    log_widget = ScrolledText(main, height=10,width=70,state="disabled",background="#1e1e1e",foreground="#cfcfcf",font=("Consolas", 9),borderwidth=1,relief="solid")
    log_widget.pack(fill="both", expand=True, pady=(0, 10))
    start_button = ttk.Button(main,text="Start Installation",style="Install.TButton",command=start_installation)
    start_button.pack(anchor="e")

def main() -> None:
    build_ui()
    assert root is not None
    root.mainloop()

if __name__ == "__main__":
    main()