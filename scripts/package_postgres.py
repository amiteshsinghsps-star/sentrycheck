"""Package the locally built, trusted PostgreSQL fixture and its Linux dependencies.

This is a corpus builder, not an extractor for arbitrary/untrusted host executables.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    files = {}
    def add(name, path):
        data = path.read_bytes()
        files[name] = (data, path.stat().st_mode & 0o777)
        if data[:4] == b'\x7fELF':
            result = subprocess.run(['ldd', str(path)], capture_output=True, text=True, check=False)
            if result.returncode and 'not a dynamic executable' not in result.stderr:
                raise ValueError(result.stderr)
            for dependency in re.findall(r'(?:=>\s*)?(/[^\s(]+)', result.stdout):
                dep = Path(dependency)
                files[dependency.lstrip('/')] = (dep.read_bytes(), dep.stat().st_mode & 0o777)
    for path in sorted(args.rootfs.rglob('*')):
        if path.is_file(): add(path.relative_to(args.rootfs).as_posix(), path)
    for name in ['sh', 'mktemp', 'cat', 'tail', 'cp', 'chmod']:
        add('bin/' + name, Path('/bin/' + name))
    files['etc/passwd'] = (b'root:x:0:0:root:/root:/bin/sh\nsentrycheck:x:10001:10001:Postgres:/tmp:/bin/sh\n', 0o644)
    files['etc/group'] = (b'root:x:0:\nsentrycheck:x:10001:\n', 0o644)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as archive:
        # Empty PostgreSQL state directories are semantically required.
        for path in sorted(args.rootfs.rglob('*')):
            if path.is_dir():
                info = tarfile.TarInfo(path.relative_to(args.rootfs).as_posix())
                info.type, info.mode, info.mtime = tarfile.DIRTYPE, path.stat().st_mode & 0o777, 0
                archive.addfile(info)
        for name, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, 0
            archive.addfile(info, io.BytesIO(data))
    content = raw.getvalue()
    blobs = args.out / 'blobs/sha256'
    blobs.mkdir(parents=True, exist_ok=True)
    def compact(value): return json.dumps(value, separators=(',', ':')).encode()
    def digest(data): return 'sha256:' + hashlib.sha256(data).hexdigest()
    def blob(data, media):
        identity = digest(data)
        (blobs / identity[7:]).write_bytes(data)
        return {'mediaType': media, 'digest': identity, 'size': len(data)}
    layer = blob(gzip.compress(content, mtime=0), 'application/vnd.oci.image.layer.v1.tar+gzip')
    config = blob(compact({'architecture': 'amd64', 'os': 'linux', 'config': {'User': '10001:10001', 'Env': ['PATH=/opt/pgsql/bin:/bin', 'LC_ALL=C'], 'Entrypoint': ['/opt/pgsql/bin/postgres'], 'Cmd': ['--version'], 'WorkingDir': '/'}, 'rootfs': {'type': 'layers', 'diff_ids': [digest(content)]}}), 'application/vnd.oci.image.config.v1+json')
    manifest = blob(compact({'schemaVersion': 2, 'config': config, 'layers': [layer]}), 'application/vnd.oci.image.manifest.v1+json')
    manifest['platform'] = {'architecture': 'amd64', 'os': 'linux'}
    (args.out / 'index.json').write_bytes(compact({'schemaVersion': 2, 'manifests': [manifest]}))
    (args.out / 'oci-layout').write_bytes(compact({'imageLayoutVersion': '1.0.0'}))
    print('Packaged PostgreSQL image', manifest['digest'], len(files), 'files')


if __name__ == '__main__':
    main()
