# installer

print("this script is not finished yet")
exit(1)

import subprocess
import sys
import os

LIBRARIES = {
    'pyjwt': {'install': 'pyjwt', 'import': 'jwt'},
    'Jinja2': {'install': 'Jinja2', 'import': 'jinja2'},
    'urllib3': {'install': 'urllib3', 'import': 'urllib3'},
    'uvicorn': {'install': 'uvicorn', 'import': 'uvicorn'},
    'fastapi[standard]': {'install': 'fastapi[standard]', 'import': 'fastapi'},
    'requests': {'install': 'requests', 'import': 'requests'},
    'pydantic': {'install': 'pydantic', 'import': 'pydantic'},
    'websockets': {'install': 'websockets', 'import': 'websockets'},
    'MarkupSafe': {'install': 'MarkupSafe', 'import': 'markupsafe'},
    'argon2-cffi': {'install': 'argon2-cffi', 'import': 'argon2'},
    'pycryptodome': {'install': 'pycryptodome', 'import': 'Crypto'},
    'cryptography': {'install': 'cryptography', 'import': 'cryptography'},
    'python-dotenv': {'install': 'python-dotenv', 'import': 'dotenv'},
    'python-multipart': {'install': 'python-multipart', 'import': 'multipart'},
}

BASEDIR = os.path.abspath(os.path.dirname(__file__))

print("INSTALLER FOR PRIVATE SAFE MESSAGING (PSM)")
print("CLIENT VERSION 2.1.0 (built 12:30 GMT+0 5/11/2025)")
python_version = subprocess.check_output(["python", "-V", "-V"], text=True).strip()
print(f"PYTHON VERSION: {python_version}")
try:
    pip_version = subprocess.check_output(["pip", "-V"], text=True).strip()
except Exception as e:
    print(f"ERROR: {e}")
    print("FATAL ERROR, pip not found")
    print("install pip and try again")
    _ = input("PRESS ENTER TO EXIT")
    exit(1)
print(f"PIP VERSION: {pip_version}")
print("Preparation ended...")

print("\n\n\n" + "="*30)
print("STAGE 1, LIBRARY INSTALLATION")
print("This installer will now install the required libraries.")
print(f"The libraries to be installed are:")
for name, lib in LIBRARIES.items():
    print(name, end=" ")
print("\nPress ENTER to start the installer:")
input()
for name, lib in LIBRARIES.items():
    print("")
    try:
        __import__(lib['import'])
        print(f"{name} is already installed.")
    except ImportError:
        print(f"{name} is not installed. Installing...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', lib['install']])
            print(f"{name} installed successfully.")
        except Exception as e:
            print(f"FAILED TO INSTALL {name}: {e}.")
            _ = input("PRESS ENTER TO EXIT")
            exit(1)
print("\nAll libraries are installed.")
print("\n\n\n" + "="*30)

print("STAGE 2, GIT INSTALLATION")
print("Checking git installation...")
while True:
    try:
        git_version = subprocess.check_output(["git", "-v"], text=True).strip()
        print(f"git found, VERSION: {git_version}")
        break
    except Exception as e:
        print(f"ERROR: {e}")
    print("git not found")
    print("This setup will now explain how to install git.")
    print("1 - Visit this website bellow and select the git version for your system.")
    print("    git install website: https://git-scm.com/install/")
    print("2 - Run the installer")
    print("3 - Accept GNU General Public License")
    print("4 - Dont change the destination path and press Next")
    print("5 - Dont change the default components and press Next")
    print("6 - Dont change the default start menu folder and press Next")
    print("7 - Select the default editor to Notepad (or your favorite text editor) and press Next")
    print("8 - Select \"Let git decide\" and press Next")
    print("9 - Select \"Git from command line and also 3rd-party software (recommended option)\" and press Next")
    print("10 - Select \"Use bundled OpenSSH\" and press Next")
    print("11 - Select \"Use native Windows Security Channel library\" and press Next")
    print("12 - Select \"Checkout Windows-style, commit Unix-style line endings\" and press Next")
    print("13 - Select \"Use MinTTY (the default terminal of MSYS2)\" and press Next")
    print("14 - Select \"Fast-forward or merge\" and press Next")
    print("15 - Select \"Git Credential Manager\" and press Next")
    print("16 - Select \"Enable file system caching\" and press Install")
    print("Press ENTER to continue after the installation of git")
    _ = input()
    continue

print("STAGE 3, CMAKE INSTALLATION")
print("Checking CMake installation...")
while True:
    try:
        cmake_version = subprocess.check_output(["cmake", "-version"], text=True).strip()
        print(f"CMake found, VERSION:\n{cmake_version}")
        break
    except Exception as e:
        print(f"ERROR: {e}")
    print("CMake not found")
    print("This setup will now explain how to install CMake.")
    print("1 - Visit this website bellow and select the CMake version for your system.")
    print("    CMake install website: https://cmake.org/download/")
    ######
    print("2 - Run the installer")
    print("3 - Accept GNU General Public License")
    print("4 - Dont change the destination path and press Next")
    print("5 - Dont change the default components and press Next")
    print("6 - Dont change the default start menu folder and press Next")
    print("7 - Select the default editor to Notepad (or your favorite text editor) and press Next")
    print("8 - Select \"Let git decide\" and press Next")
    print("9 - Select \"Git from command line and also 3rd-party software (recommended option)\" and press Next")
    print("10 - Select \"Use bundled OpenSSH\" and press Next")
    print("11 - Select \"Use native Windows Security Channel library\" and press Next")
    print("12 - Select \"Checkout Windows-style, commit Unix-style line endings\" and press Next")
    print("13 - Select \"Use MinTTY (the default terminal of MSYS2)\" and press Next")
    print("14 - Select \"Fast-forward or merge\" and press Next")
    print("15 - Select \"Git Credential Manager\" and press Next")
    print("16 - Select \"Enable file system caching\" and press Install")
    print("Press ENTER to continue after the installation of git")
    _ = input()
    continue
