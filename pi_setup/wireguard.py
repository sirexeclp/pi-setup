import subprocess
from pathlib import Path
from typing import Union, List


def gpg_add(apt_keyring_file: Union[str, Path], keyserver: str, fingerprints: Union[str, List[str]]):
    apt_keyring_file = Path(apt_keyring_file)
    if not isinstance(fingerprints, list):
        fingerprints = [fingerprints]
    process = subprocess.run(["sudo", "gpg", "--no-default-keyring", "--keyring", str(apt_keyring_file.absolute()),
                              "--keyserver", keyserver, "--recv-keys"] + fingerprints)

def enable_backports(rootfs):
    # add repo to sources.list
    repo = "deb http://deb.debian.org/debian buster-backports main\n"
    path = rootfs / Path("etc/apt/sources.list.d/backports.list")
    path.write_text(repo)

    # add keys
    key_ring = rootfs / "etc/apt/trusted.gpg"
    gpg_add(key_ring, "keyserver.ubuntu.com", ["648ACFD622F3D138", "04EE7237B7D453EC"])

    apt_install(["wireguard", "raspberrypi-kernel-headers", "-t buster-backports"],update=True)

