import argparse
import json
import sys
from .stage1 import Stage1Exploit
from .stage2 import Stage2Exploit
from .exceptions import ZygoteInjectionException


def print_summary(report):
    status = report['status']
    if status in ('PREPARED', 'ALREADY_PREPARED'):
        print('OEM-unlock preparation verified.')
        print('  OEM restriction: ' + ('cleared this run.' if report['restrictionCleared'] else 'already clear.'))
        print('  User allowance: ' + ('enabled this run.' if report['userAllowanceChangedThisRun'] else 'already enabled.'))
        print('  Carrier allowance: allowed.')
        print('No bootloader unlock or reboot performed. Reboot persistence has not been checked.')
    else:
        print('Preparation incomplete: ' + status.replace('_', ' ').lower() + '.')
        if report.get('restrictionCleared'):
            print('  OEM restriction was confirmed cleared during this run.')
        if report.get('userAllowanceChangedThisRun'):
            print('  User allowance was confirmed enabled during this run.')
        print(report.get('error', report.get('message', '')))
        if report.get('setterAttempted'):
            print('Changes may have taken effect. Read the current state before retrying.')
    print('Use --verbose to include the full JSON audit log.')


def main():
    parser = argparse.ArgumentParser(description='Gabb Z2 OEM-unlock preparation (enabled by default; no bootloader unlock)')
    parser.add_argument('--serial', help='ADB serial; optional when exactly one device is connected')
    parser.add_argument('--no-oem-unlock', action='store_true', help='Run Stage 1 only; skip OEM restriction and allowance changes')
    parser.add_argument('--prepare-gabb-z2-oem-unlock', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--acknowledge-oem-unlock', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--verbose', action='store_true', help='Include the full JSON report and command audit')
    parser.add_argument('--skip-firmware-check', action='store_true', help='Compatibility option; exact firmware builds are no longer restricted')
    args = parser.parse_args()
    if args.no_oem_unlock:
        print('OEM-unlock preparation disabled; running Stage 1 only.')
    else:
        print('OEM-unlock preparation enabled. A later manual bootloader unlock may erase all data.')
    try:
        stage1 = Stage1Exploit(device_serial=args.serial)
    except ZygoteInjectionException as error:
        print('Device selection failed: ' + str(error) + '. Use --serial when multiple devices are connected.', file=sys.stderr)
        return 1
    print('Selected device: ' + stage1.device.serial)
    if not stage1.exploit_stage1():
        print('Stage 1 failed; Stage 2 not started', file=sys.stderr)
        return 1
    if args.no_oem_unlock:
        print('Stage 1 complete. OEM-unlock preparation skipped.')
        return 0
    report = Stage2Exploit().exploit_stage2(prepare_gabb_z2=True, acknowledged=True)
    print_summary(report)
    if args.verbose:
        print('\nFull audit report:')
        print(json.dumps(report, indent=2))
    return 0 if report['status'] in ('PREPARED', 'ALREADY_PREPARED') else 1


if __name__ == '__main__':
    sys.exit(main())
