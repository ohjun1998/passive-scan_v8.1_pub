#!/usr/bin/env python3
"""Install checksum-pinned ProjectDiscovery binaries on Linux x86_64."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import tempfile
import urllib.request
import zipfile

MAX_ARCHIVE = 256 * 1024 * 1024


def install(name, spec, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.probe-install-', dir=destination) as work:
        archive = Path(work) / 'tool.zip'
        digest = hashlib.sha256()
        received = 0
        with urllib.request.urlopen(spec['url'], timeout=60) as response, archive.open('wb') as stream:
            for block in iter(lambda: response.read(65536), b''):
                received += len(block)
                if received > MAX_ARCHIVE:
                    raise ValueError('Tool download exceeds size limit')
                digest.update(block)
                stream.write(block)
        if digest.hexdigest() != spec['sha256']:
            raise ValueError('Tool checksum mismatch')
        executable = Path(work) / name
        with zipfile.ZipFile(archive) as package:
            entry = package.getinfo(name)
            if entry.file_size > MAX_ARCHIVE or entry.is_dir():
                raise ValueError('Unexpected executable archive entry')
            with package.open(entry) as source, executable.open('wb') as target:
                for block in iter(lambda: source.read(65536), b''):
                    target.write(block)
        executable.chmod(0o755)
        os.replace(executable, destination / name)
    print(name + ' ' + spec['version'] + ': checksum verified')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tool', choices=('httpx', 'katana'), action='append')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
        parser.error('Pinned archives are for Linux x86_64 only')
    lock = json.loads(Path(__file__).with_name('probe-tools.json').read_text())
    for name in args.tool or ('httpx', 'katana'):
        install(name, lock[name], args.output.resolve())


if __name__ == '__main__':
    main()
