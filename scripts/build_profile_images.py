"""Package trusted corpus binaries; append Node's helper as a digest-bound OCI layer.

No Docker daemon is needed. The caller supplies a pinned, local Node OCI layout
and the binaries built from this repository. This is not an untrusted unpacker.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile

from make_fixtures import oci


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode()


def node_image(base, output, helper):
    if output.exists():
        raise ValueError('Choose a new output directory; corpus builders do not replace images')
    index = json.loads((base / 'index.json').read_text())
    manifests = [m for m in index['manifests'] if m.get('platform', {}).get('architecture', 'amd64') == 'amd64']
    if len(manifests) != 1:
        raise ValueError('Node base must resolve to one amd64 OCI manifest')
    def read_blob(descriptor):
        name = descriptor['digest']
        if not name.startswith('sha256:') or len(name) != 71 or any(c not in '0123456789abcdef' for c in name[7:]):
            raise ValueError('Invalid OCI digest')
        data = (base / 'blobs/sha256' / name[7:]).read_bytes()
        if len(data) != descriptor['size'] or digest(data) != name:
            raise ValueError('Node base blob integrity mismatch')
        return data
    manifest = json.loads(read_blob(manifests[0]))
    config = json.loads(read_blob(manifest['config']))
    if config.get('os') != 'linux' or config.get('architecture') != 'amd64':
        raise ValueError('Expected linux/amd64 Node image')
    blobs = output / 'blobs/sha256'
    blobs.mkdir(parents=True)
    for layer in manifest['layers']:
        # Verify compressed bytes before preserving them, without unpacking paths.
        data = read_blob(layer)
        (blobs / layer['digest'][7:]).write_bytes(data)
    content = io.BytesIO()
    root = Path(__file__).resolve().parents[1]
    with tarfile.open(fileobj=content, mode='w') as archive:
        for name, data, mode in [('workload/uring-helper', helper.read_bytes(), 0o755),
                                 ('workload/uring.js', (root / 'corpus/node-uring/main.js').read_bytes(), 0o644)]:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, 0
            archive.addfile(info, io.BytesIO(data))
    raw = content.getvalue()
    def write_blob(data, media):
        identity = digest(data)
        (blobs / identity[7:]).write_bytes(data)
        return {'mediaType': media, 'digest': identity, 'size': len(data)}
    manifest['layers'].append(write_blob(gzip.compress(raw, mtime=0), 'application/vnd.oci.image.layer.v1.tar+gzip'))
    config['rootfs']['diff_ids'].append(digest(raw))
    config['config']['Entrypoint'] = ['node', '/workload/uring.js']
    config['config']['Cmd'] = []
    manifest['config'] = write_blob(encode(config), 'application/vnd.oci.image.config.v1+json')
    result = write_blob(encode(manifest), 'application/vnd.oci.image.manifest.v1+json')
    result['platform'] = {'architecture': 'amd64', 'os': 'linux'}
    (output / 'index.json').write_bytes(encode({'schemaVersion': 2, 'manifests': [result]}))
    (output / 'oci-layout').write_bytes(encode({'imageLayoutVersion': '1.0.0'}))
    return {'base_manifest': manifests[0]['digest'], 'manifest': result['digest'], 'helper_sha256': digest(helper.read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node-base', type=Path)
    parser.add_argument('--uring-helper', type=Path)
    parser.add_argument('--ebpf-binary', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if bool(args.node_base) != bool(args.uring_helper):
        parser.error('--node-base and --uring-helper must be supplied together')
    if not args.node_base and not args.ebpf_binary:
        parser.error('Supply at least one corpus workload')
    args.out.mkdir(parents=True, exist_ok=True)
    results = {}
    if args.node_base:
        results['node-io-uring'] = node_image(args.node_base, args.out / 'node-io-uring', args.uring_helper)
    if args.ebpf_binary:
        destination = args.out / 'cilium-ebpf'
        if destination.exists():
            raise ValueError('Choose a new cilium-ebpf image directory')
        results['cilium-ebpf'] = {'manifest': oci(destination, {'workload': args.ebpf_binary.read_bytes()}),
                                  'binary_sha256': digest(args.ebpf_binary.read_bytes())}
    (args.out / 'build-identities.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
