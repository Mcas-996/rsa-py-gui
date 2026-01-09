# RSA 

A modern desktop application for RSA encryption and decryption, built with Python and Slint UI framework.

## Features

- Generate RSA key pairs (2048-bit)
- Encrypt messages using OAEP padding with SHA-256
- Decrypt ciphertext using OAEP padding with SHA-256
- Modern, responsive graphical interface

## Requirements

- Python 3.13 or higher
- Windows, macOS, or Linux

## Installation

### 1. Download and Install uv

**Windows (PowerShell):**
```powershell
irm https://astral.sh/uv/install.ps1 | iex
```

**macOS / Linux:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Install Dependencies

```bash
uv sync
```

## Usage

### Run the Application

```bash
uv run python main.py
```

### Run the Test Script

```bash
uv run python test.py
```

## Project Structure

```
RSA_GUI/
├── main.py           # Application entry point
├── rsaa.py           # RSA core encryption class
├── app-window.slint  # Slint UI definition file
├── test.py           # RSA encryption test script
├── pyproject.toml    # Poetry project configuration
└── README.md         # This file
```

## Dependencies

| Package | Version |
|---------|---------|
| cryptography | >= 46.0.3 |
| slint | >= 1.14.1b1 |

## License

MIT License
