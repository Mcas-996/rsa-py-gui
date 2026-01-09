# RSA GUI

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

```bash
# Install dependencies using pip
pip install -e .
```

Or using Poetry:

```bash
poetry install
```

## Usage

### Run the Application

```bash
python main.py
```

### Run the Test Script

```bash
python test.py
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
