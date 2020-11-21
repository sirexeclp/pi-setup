import json
import re
import subprocess
from pathlib import Path
from typing import List, Union, Dict


def select_sd_card(cards: List["BlockDevice"], strat=None):
    if  len(cards) == 0:
        raise IOError("No SD-card found.")
    elif len(cards) == 1:
        return cards[0]
    elif strat == "first":
        return cards[0]
    elif strat is None:
        raise IOError("More than one SD-card found.")


class DeviceManager:

    @staticmethod
    def lsblk() -> Dict:
        """Call lsblk commandline utility with -O (all data) and -J (JSON outpu) and return the output as dict."""
        process = subprocess.run(["lsblk", "-O", "-J"], capture_output=True)
        result = json.loads(process.stdout)
        return result

    @staticmethod
    def get_devices() -> List["BlockDevice"]:
        devices = DeviceManager.lsblk()["blockdevices"]
        devices = list(map(BlockDevice, devices))
        return devices

    @staticmethod
    def get_sd_cards() -> List["BlockDevice"]:
        devices = DeviceManager.get_devices()
        devices = [x for x in devices if not x.is_loop_or_optical]
        devices = [x for x in devices if not x.is_system]
        return devices


class Udisksctl:
    """An OOWrapper around the udisksctl CLI.
    """

    @staticmethod
    def _run(command: str, device_path: str) -> str:
        args = ["udisksctl", command, "-b", device_path]
        process = subprocess.run(args, capture_output=True)
        return process.stdout.decode("UTF-8")

    @staticmethod
    def mount(device_path: Union[str, Path]) -> Path:
        device_path = Path(device_path)
        # some distros (open suse) add a dot to the end of udisksctl output
        regex = "Mounted (.*?) at (.*?)\\.?$"
        result = Udisksctl._run("mount", str(device_path))
        try:
            mount_point = Path(re.match(regex, result).group(2))
            return mount_point
        except:
            raise Exception(result)


    @staticmethod
    def unmount(device_path: Union[str, Path]):
        regex = "Unmounted (.*?)\\.$"
        result = Udisksctl._run("unmount", device_path)
        return re.match(regex, result).group(1)


class BlockDevice:
    """Class to represent and manage block devices."""

    def __init__(self, raw_dict):
        self.raw_dict = raw_dict
        self.read_only = raw_dict["ro"]
        self.name = raw_dict["name"]
        self.path = raw_dict["path"]
        self.label = raw_dict.get("label", None)
        self.vendor = raw_dict.get("vendor", None)
        self.size = raw_dict.get("size", None)
        self.mount_point = BlockDevice.prepare_mounts(raw_dict["mountpoint"])
        self.children = list(map(BlockDevice, raw_dict.get("children", [])))

    @staticmethod
    def prepare_mounts(mounts):
        if mounts is None:
            return None
        elif isinstance(mounts, str):
            return Path(mounts)
        else:
            mount_paths = [Path(p) for p in mounts]
            if len(mount_paths) == 1:
                mount_paths = mount_paths[0]
            return mount_paths

    @property
    def is_removable(self):
        return self.raw_dict["rm"] or self.raw_dict["hotplug"] or self.is_virtual

    @property
    def is_loop_or_optical(self):
        regex = "^/dev/(loop|sr|ram)"
        return bool(re.match(regex, self.raw_dict["path"]))

    @property
    def is_virtual(self):
        regex = "^(block)$"
        return bool(re.match(regex, self.raw_dict["subsystems"], re.IGNORECASE))

    @property
    def is_system(self):
        return (not self.is_removable) and (not self.is_virtual)

    def mount(self):
        self.unmount()
        if self.mount_point is None:
            self.mount_point = Udisksctl.mount(self.path)

        return self.mount_point

    def unmount(self):
        if self.mount_point is not None:
            return Udisksctl.unmount(self.path)

    def mount_children(self):
        return [c.mount() for c in self.children]

    def unmount_children(self):
        return [c.unmount() for c in self.children]

    def __str__(self):
        result = f"Device({self.path}, virtual: {self.is_virtual}, removable: {self.is_removable}," \
                 f" is_system: {self.is_system}, mnt: {self.mount_point})"
        result += ":" if len(self.children) > 0 else ""
        result += "".join([f"\n\t{str(x)}" for x in self.children])
        return result

    def __repr__(self):
        return str(self)

    def __truediv__(self, other):
        return self.mount_point / other

    def __enter__(self):
        self.mount_children()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.unmount_children()

    def pretty_print(self):
        name = self.label if self.label is not None else tuple(c.label for c in self.children)
        print(name, self.size, self.path, self.vendor)
