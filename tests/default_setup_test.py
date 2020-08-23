from itertools import filterfalse

from src import pi_setup

import re


def is_readonly(device):
    return device


class BlockDevice:
    def __init__(self, raw_dict):
        self.raw_dict = raw_dict
        self.read_only = raw_dict["ro"]
        self.name = raw_dict["name"]
        self.path = raw_dict["path"]

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

    def __str__(self):
        return f"Device({self.path}, virtual: {self.is_virtual}, removable: {self.is_removable}, is_system: {self.is_system})"


if __name__ == '__main__':
    devices = pi_setup.lsblk()["blockdevices"]
    devices = list(map(BlockDevice, devices))
    devices = [x for x in devices if not x.is_loop_or_optical]
    devices = [x for x in devices if not x.is_system]  # list(filterfalse(BlockDevice.is_system, devices))
    # print([x["path"] for x in devices])
    for d in devices:
        print(d)
        # print(is_loop_or_optical(d), is_virtual(d), d["name"], d["subsystems"], d["ro"])
    print(devices)
