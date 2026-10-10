"""Replace updater API asset URLs with verified direct release download URLs."""

import argparse
import json
from pathlib import Path


def fix_urls(manifest: dict, release: dict, repository: str) -> dict:
    tag = f"desktop-v{manifest['version']}"
    if release['tag_name'] != tag:
        raise ValueError('Release tag does not match updater version')
    prefix = f'https://github.com/{repository}/releases/download/{tag}/'
    assets = {}
    for asset in release['assets']:
        direct = asset['browser_download_url']
        if not direct.startswith(prefix) or '/' in direct[len(prefix):]:
            raise ValueError('Invalid release asset download URL')
        assets[asset['url']] = direct
        assets[direct] = direct
    # Validate every entry before changing the document.
    replacements = []
    for platform in manifest['platforms'].values():
        direct = assets[platform['url']]
        if not platform['signature'].strip():
            raise ValueError('Missing updater signature')
        replacements.append((platform, direct))
    for platform, direct in replacements:
        platform['url'] = direct
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('release', type=Path)
    parser.add_argument('--repository', required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
    release = json.loads(args.release.read_text(encoding='utf-8-sig'))
    fix_urls(manifest, release, args.repository)
    args.manifest.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
