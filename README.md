# Private Safe Messaging (PSM) Client

This project is a quantum safe E2EE messaging app. It uses NIST approved algorithms.

## Features
- Uses KYBER-768 and HKDF for key encapsulation
- Uses ML-DSA-65 for signing and token management
- Uses AES-256-GCM (with Argon2id) for symmetric encryption
- Works on localhost
- Completely open source

## Installation
the installation bellow is for windows based systems.

### Requirements
- python 3.11 (https://www.python.org/downloads/release/python-3119/)
- cmake (https://cmake.org/download/)
- git (https://git-scm.com/install/)
- visual studio community, desktop development with C++ (https://visualstudio.microsoft.com/vs/)
- the code of this project

### downloading the code
1. press on the button "Code" on this repository and press "Download ZIP"
2. Extract the ZIP file where you can access easly

### python setup
1. Open the python 3.11 installer
2. Make sure to check "Use admin privileges when installing py.exe" and "Add python.exe to PATH"
3. Press "Install Now"
4. After installation of python, go to where you extracted the ZIP and type ```bash pip install -r requirements.txt``` on CMD
5. After all libraries are installed, move on to the next steps

### git setup
Basicly just use the default values
1. Continue with the default components
2. Use Notepad as Git's default editor (or choose your other favorite text editor)
3. Let Git decide
4. Git from command line and also 3rd-party software (recommended option)
5. Use bundled OpenSSH
6. Use native Windows Security Channel library
7. Checkout Windows-style, commit Unix-style line endings
8. Use MinTTY
9. Fast-forward or merge
10. Git Credential Manager
11. Enable file system caching
12. Press install
13. After installation, move on to the next steps

### cmake setup


### visual studio community, desktop development with C++ setup
1. run the installer, make sure its community version
2. select "desktop development with C++ setup" from available apps
3. do not change any default options and press install
4. After installation, move on to the next steps

### liboqs-python setup
1. type ```git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python``` on CMD
2. ```cd liboqs-python```
3. ```pip install .```
4. ```python -c "import oqs"```
5. if it doesnt work, create a issue here -> https://github.com/open-quantum-safe/liboqs-python

## Running the app
1. go to the directory where the zip was extracted
2. double click on ```main.py``` or run ```python main.py``` on CMD
3. wait a few moments
4. a browser window will open. you can use the system from there
