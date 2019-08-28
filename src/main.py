import json
import subprocess
import sys
from pathlib import Path

from gevent import os


def render_template(template_file, **kwargs):
    import jinja2
    template_loader = jinja2.FileSystemLoader(searchpath="./templates")
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template(template_file)
    output_text = template.render(**kwargs)
    return output_text


def check_path(path):
    path = Path(path)
    if not path.exists():
        raise IOError(f"{path} does not exist")
    return path


def enable_ssh(boot_fs):
    boot_fs = check_path(boot_fs)
    ssh_file = boot_fs / "ssh"
    open(ssh_file, 'a').close()


def configure(root_path, config_file, template_file, append=True, **kwargs):
    root_path = check_path(root_path)
    print(root_path)
    config_file = root_path / config_file
    output_text = render_template(template_file, **kwargs)
    print(output_text)
    mode = "a" if append else "w"
    print(f"writing to {config_file}")
    with config_file.open(mode) as f:
        f.write(output_text)


def configure_static_ip(rootfs, ip_address="192.168.1.31/24", interface="eth0"):
    configure(rootfs, "etc/dhcpcd.conf", "dhcpcd.conf", interface=interface, ip_address=ip_address)


def configure_wifi(boot_fs, ssid, psk):
    configure(boot_fs, "wpa_supplicant.conf", "wpa_supplicant.conf", False, ssid=ssid, psk=psk)


def lsblk():
    process = subprocess.run(["lsblk", "-O", "-J"], capture_output=True)
    result = json.loads(process.stdout)
    return result


def filter_sd_cards(devices):
    return [item for item in devices["blockdevices"] if item["rm"] and item["hotplug"] and item["tran"] == "usb"]


def get_mounts(card, filter):
    mounts = [child["mountpoint"] for child in card["children"] if filter in child["mountpoint"]]
    if len(mounts) < 1:
        raise Exception(f"No mounts found with filter '{filter}'")
    return mounts


if __name__ == "__main__":
    # if os.geteuid() != 0:
    #     subprocess.call(['sudo', 'python3', *sys.argv])
    #     sys.exit()

    devices = lsblk()
    cards = filter_sd_cards(devices)
    assert len(cards) == 1, "Error: more than one sd card found"
    boot = get_mounts(cards[0], "boot")[0]
    root_fs = get_mounts(cards[0], "rootfs")[0]
    print(boot)
    print(root_fs)
    configure_wifi(boot, "test2", "test3")
    configure_static_ip(root_fs)
