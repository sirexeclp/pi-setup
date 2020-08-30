import subprocess
from itertools import filterfalse

from colorama import Fore, Style

from src import main

import re

from src.main import PiConfigurator


class Udisksctl:

    @staticmethod
    def _run(command, device_path):
        args = ["udisksctl", command, "-b", device_path]
        process = subprocess.run(args, capture_output=True)
        return process.stdout.decode("UTF-8")

    @staticmethod
    def mount(device_path):
        regex = "Mounted (.*) at (.*)$"
        result = Udisksctl._run("mount", device_path)
        return re.match(regex, result).group(2)

    @staticmethod
    def unmount(device_path):
        regex = "Unmounted (.*)..$"
        result = Udisksctl._run("unmount", device_path)
        return  re.match(regex, result).group(1)


class BlockDevice:
    def __init__(self, raw_dict):
        self.raw_dict = raw_dict
        self.read_only = raw_dict["ro"]
        self.name = raw_dict["name"]
        self.path = raw_dict["path"]
        self.mount_point = raw_dict["mountpoint"]
        self.children = list(map(BlockDevice, raw_dict.get("children", [])))

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
        result = f"Device({self.path}, virtual: {self.is_virtual}, removable: {self.is_removable},"\
                 f" is_system: {self.is_system}, mnt: {self.mount_point})"
        result += ":" if len(self.children) > 0 else ""
        result += "".join([f"\n\t{str(x)}" for x in self.children])
        return result

def check(input, condition, is_not=False):
    if input == condition:
        return f"{Fore.GREEN}✔{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}✘{Style.RESET_ALL}"


def check_not(input, condition):
    if input != condition:
        return f"{Fore.GREEN}✔{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}✘{Style.RESET_ALL}"

def get_filtered_devices():
    devices = main.lsblk()["blockdevices"]
    devices = list(map(BlockDevice, devices))
    devices = [x for x in devices if not x.is_loop_or_optical]
    devices = [x for x in devices if not x.is_system]  # list(filterfalse(BlockDevice.is_system, devices))
    return devices

if __name__ == '__main__':
    devices = get_filtered_devices()
    # print([x["path"] for x in devices])
    for d in devices:
        print(d)
        print(d.mount_children())

        # print(is_loop_or_optical(d), is_virtual(d), d["name"], d["subsystems"], d["ro"])

    devices = get_filtered_devices()
    configurator = PiConfigurator(devices[0].raw_dict)

    hostname = configurator.get_hostname()
    ssh_enabled = configurator.is_ssh_enabled()
    default_pw = configurator.is_default_password()
    static_ip = configurator.get_static_ip()
    is_group_dialout = configurator.check_user_in_group("pi", "dialout")

    print(f"{check_not(hostname, 'raspberrypi')} Hostname: {hostname}")
    print(f"{check(ssh_enabled, True)} SSH: {'enabled' if ssh_enabled else 'disabled'}")
    print(f"{check_not(default_pw, True)} Password: {'unchanged' if default_pw else 'changed'}")
    print(f"{check_not(static_ip, None)} Static IP: {static_ip}")
    print(
        f"{check(is_group_dialout, True)} User pi is{' ' if is_group_dialout else ' not '}a member of the group dialout.")

    devices[0].unmount_children()
