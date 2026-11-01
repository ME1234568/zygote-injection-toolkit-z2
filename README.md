# Zygote injection toolkit — Gabb Z2 fork

NOTE: Run the [Z2-Liberator Setup](https://z2-liberator-beta.eth0s.dev/) BEFORE running this project to get ADB access

This fork of [Anonymous941/zygote-injection-toolkit](https://github.com/Anonymous941/zygote-injection-toolkit) adds device-specific OEM-unlock preparation for the Gabb Z2 (ZTE Z5157V), using Android Zygote injection (CVE-2024-31317).

**OEM-unlock preparation runs by default and changes device settings.** It attempts to clear the OEM-unlock restriction and enable the user allowance, while checking the carrier allowance. It does not unlock the bootloader or reboot the phone. A later manual bootloader unlock may erase all data. Successful preparation does not prove that bootloader unlocking will succeed, and persistence after reboot has not been verified.

## Compatibility

The default Stage 2 workflow is restricted to ZTE Z5157V Android 10 with this firmware fingerprint:

```text
ZTE/VZW_Z5157V/Z5157:10/QP1A.190711.020/20220816.160100:user/release-keys
```

This is the firmware allowlist encoded in the tool, not a guarantee of success on every matching device. Stage 2 also checks device state, including owner and policy restrictions, before proceeding.

Stage 1 uses the upstream vulnerability, addressed in the [June 2024 Android security bulletin](https://source.android.com/security/bulletin/2024-06-01). Its compatibility checks are separate from Stage 2's phone-specific restrictions. Other Android devices are not supported by this fork's default preparation workflow.

This provides a shell with Android `system` privileges, not root access or support for Magisk modules.

## Requirements

- Python 3.10 or newer.
- Git installed and available on `PATH`, including for the pinned Git dependencies.
- Android SDK platform-tools (`adb`) installed and available on `PATH`.
- USB debugging enabled and the host computer authorized on the phone.

## Installation and updates

Create a virtual environment and activate it using the commands for your shell.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
```

Then install this fork:

```sh
python -m pip install --upgrade pip
python -m pip install --upgrade "git+https://github.com/ME1234568/zygote-injection-toolkit-z2.git"
```

Run the same installation command to update to a newer release. The distribution name is `zygote-injection-toolkit-z2`; the Python module name remains `zygote_injection_toolkit`. Use a fresh environment when migrating from the upstream distribution, because both distributions provide the same module.

Dependencies are pinned to the commit revisions recorded in the development environment. Installation requires network access to those Git repositories. This repository is installed directly from Git; no PyPI release is assumed.

## Usage

Start ADB and confirm that the intended device is listed and authorized:

```sh
adb start-server
adb devices
python -m zygote_injection_toolkit --help
```

Run the default preparation workflow:

```sh
python -m zygote_injection_toolkit
```

| Option | Behavior |
| --- | --- |
| `--serial SERIAL` | Select an ADB device; required when multiple devices are connected. |
| `--no-oem-unlock` | Run Stage 1 only and skip Stage 2's OEM restriction and allowance changes. Stage 1 still runs the exploit. |
| `--verbose` | Include the full Stage 2 JSON report and command audit. |
| `--skip-firmware-check` | Permit testing another Z5157V Android 10 firmware fingerprint. Device identity, Android version, and other state checks remain enabled. Compatibility with other builds is unverified. |

Stage 1 establishes a shell on port 1234 through ADB forwarding. Default execution then performs Stage 2 preparation. `PREPARED` and `ALREADY_PREPARED` are successful results and produce exit code 0; failed preparation produces exit code 1. Stage 1-only execution returns 0 when Stage 1 succeeds.

If preparation reports an unknown outcome after a change was attempted, inspect the current device state before retrying. The tool does not automatically roll back changes.

The hidden `--prepare-gabb-z2-oem-unlock` and `--acknowledge-oem-unlock` arguments are retained for compatibility with older commands. They do not change behavior; preparation is already enabled by default.

## Development

```sh
git clone https://github.com/ME1234568/zygote-injection-toolkit-z2.git
cd zygote-injection-toolkit-z2
python -m pip install -e .
```

Use an activated virtual environment. Build release artifacts with:

```sh
python -m pip install build
python -m build
```

Before publishing, increment the version in `pyproject.toml`. CI builds the wheel and source distribution, checks their contents, and installs each into an isolated environment outside the source checkout. Its smoke checks import the modules and display CLI help without connecting to a phone; they do not validate device behavior.

## Changes and attribution

Version 0.2.0 identifies this Gabb Z2 fork. Compared with upstream, the working tree adds device selection and CLI reporting, replaces Stage 2 with firmware-restricted OEM-unlock preparation, and updates packaging and documentation for this fork.

The original toolkit and exploit implementation come from the upstream project and its contributors. This fork retains the GPL-3.0-or-later license; see [LICENSE](LICENSE).

Further background: [Meta's Zygote injection analysis](https://rtx.meta.security/exploitation/2024/06/03/Android-Zygote-injection.html).
