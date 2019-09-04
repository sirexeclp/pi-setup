import json
import subprocess
import sys
from pathlib import Path
import crypt, getpass, pwd
from gevent import os


def render_template(template_file, **kwargs):
    """Loads the given template from ./templates and renders it using jinja2."""
    import jinja2
    template_loader = jinja2.FileSystemLoader(searchpath="./templates")
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template(template_file)
    output_text = template.render(**kwargs)
    return output_text


def check_path(path):
    """Converts given string to Path object and throws if the path does not exist."""
    path = Path(path)
    assert path != Path("/"), "Do not use the host root here!"
    if not path.exists():
        raise IOError(f"{path} does not exist")
    return path


def enable_ssh(boot_fs):
    """Enables ssh on the pi by creating an empty file named ssh on the boot partition."""
    boot_fs = check_path(boot_fs)
    ssh_file = boot_fs / "ssh"
    open(ssh_file, 'a').close()


def configure(root_path, config_file, template_file, append=True, **kwargs):
    """Generic method that renders a config file and writes or appends it to the given destination."""
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
    """Configure the pi to use the given static ip/netmask on the given interface using dhcpcd.conf."""
    configure(rootfs, "etc/dhcpcd.conf", "dhcpcd.conf", interface=interface, ip_address=ip_address)


def configure_wifi(boot_fs, ssid, psk):
    """Configure wifi on the pi by writing wpa_supplicant.conf to the boot partition.
     wpa_supplicant.conf will be copied to the correct location and overwrite the existing config on bootup."""
    configure(boot_fs, "wpa_supplicant.conf", "wpa_supplicant.conf", False, ssid=ssid, psk=psk)


def lsblk():
    """Call lsblk commandline utility with -O (all data) and -J (JSON outpu) and return the output as dict."""
    process = subprocess.run(["lsblk", "-O", "-J"], capture_output=True)
    result = json.loads(process.stdout)
    return result


def filter_sd_cards(devices):
    """Filter devices for sd_cards. SD cards are assumed to be removable, hot pluggable and use usb as transport bus."""
    return [item for item in devices["blockdevices"] if item["rm"] and item["hotplug"] and item["tran"] == "usb"]


def get_mounts(card, filter):
    """Filter mount points of devices, by path. Throws if no matching mount point is found."""
    mounts = [child["mountpoint"] for child in card["children"] if filter in child["mountpoint"]]
    if len(mounts) < 1:
        raise Exception(f"No mounts found with filter '{filter}'")
    return mounts


def ssh_keygen(key_name, password):
    ssh_root = Path.home() / Path(".ssh")
    ssh_root.mkdir(exist_ok=True, parents=True)
    filename = ssh_root / key_name
    process = subprocess.run(["ssh-keygen", "-b", "4096", "-f", filename, "-N", password])
    return filename.with_suffix(".pub")


def get_pi_ssh_dir(rootfs, create=True):
    rootfs = check_path(rootfs)
    pi_ssh_dir = rootfs / Path("home/pi/.ssh")
    pi_ssh_dir.mkdir(exist_ok=True, parents=True)
    return check_path(pi_ssh_dir)


def get_sshd_dir(rootfs):
    rootfs = check_path(rootfs)
    filename = rootfs / "etc/ssh/sshd_config"
    filename = check_path(filename)
    return filename


def disable_password_authentication(rootfs):
    filename = get_sshd_dir(rootfs)
    options = parse_sshd_conf(filename)
    options = ["PasswordAuthentication no" if "PasswordAuthentication" in line else line for line in options]
    filename.write_text("\n".join(options))


def parse_sshd_conf(filename):
    filename = check_path(filename)
    options = filename.read_text().splitlines()
    # print(options)
    return options

def get_fingerprint(filename):
    output = subprocess.run(["ssh-keygen", "-lf", str(filename)], capture_output=True)
    if not output.stdout:
        raise FileNotFoundError(output.stderr)
    return output.stdout

def ssh_addkey(rootfs, filename):
    filename = check_path(filename)
    pi_ssh_dir = get_pi_ssh_dir(rootfs)
    authorized_keys = pi_ssh_dir / Path("authorized_keys")

    new_key = filename.read_text()
    all_keys = ""
    if authorized_keys.exists():
        all_keys = authorized_keys.read_text()
    if new_key not in all_keys:
        with authorized_keys.open("a") as f:
            f.write(new_key)
    print(f"added key {filename}")


def parse_shadow_line(line):
    values = line.split(":")
    field_names = ["user", "password", "changed", "allowed_change",
                   "required_change", "expiration_warning",
                   "inactive", "expiration", "reserved"]
    result = dict(zip(field_names, values))
    return result["user"], result


def get_shadow_file(rootfs):
    filename = rootfs / "etc/shadow"
    return check_path(filename)


def load_shadow(rootfs):
    filename = get_shadow_file(rootfs)
    lines = filename.read_text().splitlines()
    entries = dict([parse_shadow_line(e) for e in lines])
    return entries


def save_shadow(rootfs, entries):
    filename = get_shadow_file(rootfs)
    lines = [":".join(x.values()) for x in entries.values()]
    filename.write_text("\n".join(lines))
    return entries


def change_pw(rootfs, password):
    entries = load_shadow(rootfs)
    pi_user = entries["pi"]

    salt = crypt.mksalt()
    hashed_pw = crypt.crypt(password, salt)

    pi_user["password"] = hashed_pw
    save_shadow(rootfs, entries)


def change_host(hostname):
    # change name in etc/hostname
    # change name in etc/hosts
    pass


if __name__ == "__main__":
    # if os.geteuid() != 0:
    #     subprocess.call(['sudo', 'python3', *sys.argv])
    #     sys.exit()

    # devices = lsblk()
    # cards = filter_sd_cards(devices)
    # assert len(cards) == 1, "Error: more than one sd card found"
    # boot = get_mounts(cards[0], "boot")[0]
    # root_fs = get_mounts(cards[0], "rootfs")[0]
    # print(boot)
    # print(root_fs)
    # # configure_wifi(boot, "test2", "test3")
    # # configure_static_ip(root_fs)
    # pub_key = ssh_keygen("test123", "")
    # ssh_addkey(root_fs, pub_key)
    # disable_password_authentication()
    change_pw("test")
