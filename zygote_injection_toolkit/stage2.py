"""OEM preparation for Z5157V Android 10 firmware builds."""
import re
import shlex
import socket
import time
import uuid
from .exceptions import ZygoteInjectionException as Error

def parse_service_result(text):
    text = text.strip()
    if not text.startswith('Result: Parcel(') or not text.endswith(')'):
        raise Error('Incomplete Binder Parcel: ' + repr(text))
    words = []
    for line in text[len('Result: Parcel('):-1].splitlines():
        if not line.strip():
            continue
        offset = re.match(r'\s*0x([0-9a-fA-F]+):\s*', line)
        if offset:
            if int(offset[1], 16) != len(words) * 4:
                raise Error('Noncontiguous Parcel offsets')
            line = line[offset.end():]
        match = re.fullmatch(r"\s*((?:[0-9a-fA-F]{8}\s+)+)'[^']*'\s*", line)
        if not match:
            raise Error('Unsupported Parcel line: ' + repr(line))
        words.extend(int(word, 16) for word in match[1].split())
    if not words:
        raise Error('Empty Binder reply')
    return b''.join(word.to_bytes(4, 'little') for word in words)


def parse_boolean_result(data):
    if len(data) != 8 or data[:4] != bytes(4):
        raise Error('Invalid Boolean reply or Binder exception: ' + data.hex())
    value = int.from_bytes(data[4:], 'little')
    if value not in (0, 1):
        raise Error('Non-Boolean Binder value')
    return bool(value)


def owner_restrictions(dump):
    if not re.search(r'(?m)^\s*Device managed: false\s*$', dump) or not re.search(r'(?m)^\s*Device owner id:-10000\s*$', dump):
        raise Error('Managed device or unknown owner state')
    records = list(re.finditer(r'(?m)^  UserInfo\{(\d+):[^\n]+', dump))
    if len(records) != 1 or records[0][1] != '0':
        raise Error('Requires single owner user 0')
    record = dump[records[0].start():].split('\n  Device owner id:', 1)[0]
    flags = re.search(r'UserInfo\{0:[^:}\n]+:([0-9a-fA-F]+)\}', record)
    if not flags or not int(flags[1], 16) & 2:
        raise Error('Owner is not admin')
    for required in ('State: RUNNING_UNLOCKED', 'Has profile owner: false'):
        if required not in record:
            raise Error('Missing owner check: ' + required)
    sections = {}
    for heading in ('Restrictions', 'Device policy global restrictions', 'Device policy local restrictions', 'Effective restrictions'):
        matches = re.findall(r'(?m)^    ' + re.escape(heading) + r':[ \t]*\n((?:      [^\n]*\n?)*)', record)
        if len(matches) != 1 or not matches[0].strip():
            raise Error('Unknown restriction section: ' + heading)
        tokens = matches[0].split()
        if tokens in (['none'], ['null']):
            tokens = []
        elif not all(re.fullmatch(r'no_[a-z_]+', token) for token in tokens):
            raise Error('Unsupported restriction encoding')
        sections[heading] = set(tokens)
    if sections['Device policy global restrictions'] or sections['Device policy local restrictions']:
        raise Error('Device policy restrictions present')
    if 'no_factory_reset' in sections['Effective restrictions']:
        raise Error('Factory reset restriction present')
    return {'base': 'no_oem_unlock' in sections['Restrictions'], 'effective': 'no_oem_unlock' in sections['Effective restrictions']}


class Stage2Exploit:
    def __init__(self, port=1234):
        self.port = port
        self.audit = []

    def shell(self, sock, command):
        token = uuid.uuid4().hex
        begin, end = 'ZIT_BEGIN_' + token, 'ZIT_END_' + token
        script = f"printf '\\n{begin}\\n'\n" + command + '\n' + f"zit_rc=$?\nprintf '\\n{end}:%s\\n' \"$zit_rc\"\n"
        sock.sendall(script.encode())
        deadline, data = time.monotonic() + 10, bytearray()
        marker = re.compile(rb'\n' + end.encode() + rb':([0-9]+)\r?\n')
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Shell command outcome unknown')
                sock.settimeout(remaining)
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError('Shell disconnected; command outcome unknown')
                data.extend(chunk)
                if len(data) > 1024 * 1024:
                    raise Error('Shell response too large')
                match = marker.search(data)
                if match:
                    start = bytes(data).find((begin + '\n').encode())
                    if start < 0:
                        raise Error('Missing response start marker')
                    output = bytes(data[start + len(begin) + 1:match.start()]).decode('utf-8', 'strict').strip()
                    self.audit.append({'command': command, 'exit': int(match[1]), 'output': output})
                    if int(match[1]):
                        raise Error('Command failed: ' + output)
                    return output
        except Exception:
            sock.close()
            raise

    def binder(self, sock, service, code, *args, boolean=False):
        command = shlex.join(['service', 'call', service, str(code), *map(str, args)])
        data = parse_service_result(self.shell(sock, command + ' # zit-complete-command'))
        if boolean:
            return parse_boolean_result(data)
        if data != bytes(4):
            raise Error('Setter failed or unsupported reply: ' + data.hex())

    def check(self, sock):
        expected = {'id -u': '1000', 'getprop ro.build.version.sdk': '29', 'getprop ro.build.version.release': '10', 'getprop ro.oem_unlock_supported': '1', 'am get-current-user': '0'}
        fingerprint = self.shell(sock, 'getprop ro.build.fingerprint')
        if not re.fullmatch(r'ZTE/VZW_Z5157V/Z5157:10/[^/\s]+/[^/\s]+:user/release-keys', fingerprint):
            raise Error('Requires ZTE Z5157V Android 10 identity')
        for command, value in expected.items():
            if self.shell(sock, command) != value:
                raise Error('Unsupported device/session: ' + command)
        for service in ('user', 'oem_lock', 'persistent_data_block'):
            if self.shell(sock, 'service check ' + service) != f'Service {service}: found':
                raise Error('Required service unavailable: ' + service)
        return owner_restrictions(self.shell(sock, 'dumpsys user'))

    def exploit_stage2(self, *, prepare_gabb_z2=False, acknowledged=False, skip_firmware_check=False):
        # skip_firmware_check is retained as a compatibility no-op for callers.
        if not (prepare_gabb_z2 and acknowledged):
            return {'status': 'SKIPPED', 'message': 'Explicit Gabb Z2 opt-in required'}
        self.audit = []
        report = {'status': 'FAILED_BEFORE_WRITE', 'firmwarePolicy': 'Z5157V Android 10; no exact build allowlist', 'setterAttempted': False, 'restrictionCleared': False, 'userAllowanceChangedThisRun': False}
        try:
            with socket.create_connection(('127.0.0.1', self.port), timeout=10) as sock:
                original = self.check(sock)
                original['allowedByUser'] = self.binder(sock, 'oem_lock', 5, boolean=True)
                report['original'] = original.copy()
                if original['base']:
                    report['setterAttempted'] = True
                    self.binder(sock, 'user', 35, 's16', 'no_oem_unlock', 'i32', 0, 'i32', 0)
                state = self.check(sock)
                if state['base'] or state['effective']:
                    raise Error('OEM restriction still effective')
                report['restrictionCleared'] = original['base']
                if not self.binder(sock, 'oem_lock', 3, boolean=True):
                    raise Error('Carrier allowance false; stopped')
                if not original['allowedByUser']:
                    report['setterAttempted'] = True
                    self.binder(sock, 'oem_lock', 4, 'i32', 1)
                if not self.binder(sock, 'oem_lock', 5, boolean=True):
                    raise Error('User allowance readback false')
                report['userAllowanceChangedThisRun'] = not original['allowedByUser']
                if not self.binder(sock, 'oem_lock', 3, boolean=True):
                    raise Error('Carrier allowance changed')
                state = self.check(sock)
                if state['base'] or state['effective']:
                    raise Error('Restriction returned during verification')
                report['final'] = {'restrictionPresent': False, 'allowedByUser': True, 'allowedByCarrier': True}
                report['status'] = 'PREPARED' if report['setterAttempted'] else 'ALREADY_PREPARED'
                report['message'] = 'Android allowance verified. No bootloader unlock or reboot performed. Persistence untested.'
        except Exception as error:
            report['status'] = 'UNKNOWN' if report['setterAttempted'] else 'FAILED_BEFORE_WRITE'
            report['error'] = str(error)
            report['message'] = 'No automatic retry or rollback. Read current state before proceeding.'
        report['audit'] = self.audit
        return report
