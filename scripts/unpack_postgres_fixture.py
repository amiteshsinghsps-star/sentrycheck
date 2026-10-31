"""Unpack this project's single-layer PostgreSQL build fixture for seeded-data setup."""
import argparse
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--image', type=Path, required=True)
parser.add_argument('--rootfs', type=Path, required=True)
args = parser.parse_args()
def blob(descriptor):
    identity = descriptor['digest']
    if not identity.startswith('sha256:') or len(identity) != 71 or any(c not in '0123456789abcdef' for c in identity[7:]):
        raise ValueError('invalid fixture digest')
    data = (args.image / 'blobs/sha256' / identity[7:]).read_bytes()
    if len(data) != descriptor['size'] or hashlib.sha256(data).hexdigest() != identity[7:]:
        raise ValueError('fixture digest mismatch')
    return data
index = json.loads((args.image / 'index.json').read_text(encoding='utf-8'))
if len(index['manifests']) != 1: raise ValueError('expected one fixture manifest')
manifest = json.loads(blob(index['manifests'][0]))
if len(manifest['layers']) != 1: raise ValueError('expected the single-layer source-built fixture')
config = json.loads(blob(manifest['config']))
data = gzip.decompress(blob(manifest['layers'][0]))
if config['rootfs']['diff_ids'] != ['sha256:' + hashlib.sha256(data).hexdigest()]:
    raise ValueError('fixture diff_id mismatch')
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
    archive.extractall(args.rootfs, filter='data')
print('Reusing verified PostgreSQL fixture', index['manifests'][0]['digest'])
