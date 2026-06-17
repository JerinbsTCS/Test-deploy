# Using Semgrep Locally

A guide to installing and running Semgrep on your local machine for static analysis scanning.

---

## Prerequisites

- **Python** must be installed (3.8+)

---

## Installation

### 1. Install Semgrep via pip

```bash
pip install semgrep
```

### 2. Verify Installation

```bash
semgrep --version
```

---

## If Installation Fails (Virtual Environment)

If the direct install fails (e.g. permission issues or conflicts), use a virtual environment:

### 1. Navigate to a safe directory and create a venv

```bash
python -m venv .venv
```

### 2. Activate the virtual environment

=== "Windows (PowerShell)"

    ```powershell
    .\.venv\Scripts\Activate.ps1
    ```

=== "Windows (CMD)"

    ```cmd
    .\.venv\Scripts\activate.bat
    ```

=== "Linux / macOS"

    ```bash
    source .venv/bin/activate
    ```

### 3. Install Semgrep inside the venv

```bash
pip install semgrep
```

### 4. Verify Installation

```bash
semgrep --version
```

---

## Login & Pro Engine

### 1. Login to Semgrep

```bash
semgrep login
```

### 2. Install the Pro Engine

```bash
semgrep install-semgrep-pro
```

---

## Running a Scan

### 1. Navigate to your code/repo folder

```bash
cd /path/to/your/project
```

### 2. Run Semgrep CI in dry-run mode

```bash
semgrep ci --dry-run
```

---

## Troubleshooting

!!! warning "Windows Codec Error"

    If you encounter a codec/encoding error on Windows, set the following environment variable before running semgrep:

    ```powershell
    $env:PYTHONUTF8="1"
    ```

    Then re-run the scan:

    ```powershell
    semgrep ci --dry-run
    ```
