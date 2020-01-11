import crypt
import json
import re
import shutil
import subprocess
from pathlib import Path
import os
import yaml

DRY_RUN = True


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
    # assert path != Path("/"), "Do not use the host root here!"
    if not path.exists():
        raise IOError(f"{path} does not exist")
    return path


def auto_select_sd_card():
    devices = lsblk()
    cards = filter_sd_cards(devices)
    assert len(cards) > 0, "Error: no sd card found"
    assert len(cards) == 1, "Error: more than one sd card found"
    return cards[0]


def lsblk():
    """Call lsblk commandline utility with -O (all data) and -J (JSON outpu) and return the output as dict."""
    process = subprocess.run(["lsblk", "-O", "-J"], capture_output=True)
    result = json.loads(process.stdout)
    return result


def filter_sd_cards(devices):
    """Filter devices for sd_cards. SD cards are assumed to be removable, hot pluggable and use usb as transport bus."""
    return [item for item in devices["blockdevices"] if item["rm"] and item["hotplug"] and item["tran"] == "usb"]


def configure(root_path, config_file, template_file, append=True, **kwargs):
    """Generic method that renders a config file and writes or appends it to the given destination."""
    root_path = check_path(root_path)
    config_file = root_path / config_file
    output_text = render_template(template_file, **kwargs)
    original_config = config_file.read_text() if config_file.exists() else ""
    if output_text in original_config:
        return
    mode = "a" if append else "w"
    print(f"{'appending' if append else 'writing'} to {config_file}")

    if not DRY_RUN:
        with config_file.open(mode) as f:
            f.write(output_text)
    else:
        print(output_text)


def ssh_keygen(key_name, password):
    ssh_root = Path.home() / Path(".ssh")
    ssh_root.mkdir(exist_ok=True, parents=True)
    filename = ssh_root / key_name
    process = subprocess.run(["ssh-keygen", "-b", "4096", "-f", filename, "-N", password])
    return filename.with_suffix(".pub")


def set_key_value_config_file(filename, key, value, sep):
    pair = f"{key}{sep}{value}"
    config = filename.read_text()
    options = config.splitlines()
    if key in config:
        options = [pair if key in line else line for line in options]
    else:
        options.append(pair)
    filename.write_text("\n".join(options))


def get_fingerprint(filename):
    output = subprocess.run(["ssh-keygen", "-lf", str(filename)], capture_output=True)
    if not output.stdout:
        raise FileNotFoundError(output.stderr)
    return output.stdout


def get_current_wifi_ssid():
    result = subprocess.run(['iwgetid'], capture_output=True)
    regex = ".*ESSID ?:? ?\"(.*)\""
    ssid = re.match(regex, result.stdout.decode("UTF-8"))[1]
    return ssid


def get_wifi_psk(ssid):
    base = check_path(Path("/etc/NetworkManager/system-connections"))
    con_file = base / Path(f"{ssid}.nmconnection")
    connection = con_file.read_text().splitlines()
    psk = [x[4:] for x in connection if x.startswith("psk")]
    return psk[0] if len(psk) > 0 else None


def add2ssh_conf(host_alias, host_name, identity_file, user="pi", port="22", forward_agent=False):
    ssh_path = Path.home() / ".ssh"
    ssh_path.mkdir(exist_ok=True)
    ssh_config_path = ssh_path / "config"
    shutil.copyfile(ssh_config_path, ssh_config_path.with_suffix(".bck"))
    configure(ssh_path, "config", append=True,
              host_alias=host_alias, host_name=host_alias, identity_file=str(identity_file),
              user=user, port=port, forward_agent=forward_agent)


def add2known_hosts():
    # TODO: add raspberry host key to known hosts file
    pass


class PiConfigurator:
    def __init__(self, card):
        self.card = card
        self.boot = check_path(self._get_mounts("boot")[0])
        self.rootfs = check_path(self._get_mounts("rootfs")[0])

        assert str(
            self.boot) == f"/media/{os.getlogin()}/boot", f"Unexpected mount path of pi boot partition! Expected: /media/{os.getlogin()}/boot Actual: {self.boot}"
        assert str(
            self.rootfs) == f"/media/{os.getlogin()}/rootfs", f"Unexpected mount path of pi rootfs partition! Expected: /media/{os.getlogin()}/rootfs Actual: {self.rootfs}"

        print(f"boot: {self.boot}")
        print(f"rootfs: {self.rootfs}")

    def _get_mounts(self, filter_str):
        """Filter mount points of devices, by path. Throws if no matching mount point is found."""
        mounts = [child["mountpoint"] for child in self.card["children"] if filter_str in child["mountpoint"]]
        if len(mounts) < 1:
            raise Exception(f"No mounts found with filter '{filter_str}'")
        return mounts

    def enable_ssh(self):
        """Enables ssh on the pi by creating an empty file named ssh on the boot partition."""
        ssh_file = self.boot / "ssh"
        open(ssh_file, 'a').close()

    def is_ssh_enabled(self):
        ssh_file = self.boot / "ssh"
        # S --> enabled K-->stoped
        init_path = self.rootfs / "etc/rc2.d"
        ssh_enabled = [x.stem for x in init_path.iterdir()
                       if "ssh" in str(x)][0].startswith("S")

        return ssh_enabled or ssh_file.exists()

    def is_default_password(self):
        pi_user = self._load_shadow()["pi"]
        default_pw_hashed = crypt.crypt("raspberry", "$".join(pi_user["password"].split("$")[0:3]))
        return default_pw_hashed == pi_user["password"]

    def configure_static_ip(self, ip_address="192.168.3.14/24", interface="eth0"):
        """Configure the pi to use the given static ip/netmask on the given interface using dhcpcd.conf."""
        configure(self.rootfs, "etc/dhcpcd.conf", "dhcpcd.conf", interface=interface, ip_address=ip_address)

    def get_static_ip(self):
        path = self.rootfs / "etc/dhcpcd.conf"
        content = path.read_text().splitlines()
        content = [x for x in content if not x.strip().startswith("#")]
        return next(iter([x.split("=")[1] for x in content if "static ip_address" in x]), None)

    def configure_wifi(self, ssid, psk=None):
        """Configure wifi on the pi by writing wpa_supplicant.conf to the boot partition.
         wpa_supplicant.conf will be copied to the correct location and overwrite the existing config on bootup."""
        file_name = "wpa_supplicant.conf"
        configure(self.boot, file_name, file_name, False, ssid=ssid, psk=psk)
        os.chmod(check_path(self.boot / file_name), 0o600)

    def _get_pi_ssh_dir(self, create=True):
        pi_ssh_dir = self.rootfs / Path("home/pi/.ssh")
        pi_ssh_dir.mkdir(exist_ok=True, parents=True)
        return check_path(pi_ssh_dir)

    def _get_sshd_dir(self):
        return check_path(self.rootfs / "etc/ssh/sshd_config")

    def disable_password_authentication(self):
        set_key_value_config_file(filename=self._get_sshd_dir(), key="PasswordAuthentication", value="no", sep=" ")

    def ssh_addkey(self, filename):
        filename = check_path(filename)
        pi_ssh_dir = self._get_pi_ssh_dir()
        authorized_keys = pi_ssh_dir / Path("authorized_keys")

        new_key = filename.read_text()
        all_keys = ""
        if authorized_keys.exists():
            all_keys = authorized_keys.read_text()
        if new_key not in all_keys:
            with authorized_keys.open("a") as f:
                f.write(new_key)
        os.chown(pi_ssh_dir, self.get_pi_uid(), self.get_pi_uid())
        os.chown(authorized_keys, self.get_pi_uid(), self.get_pi_uid())
        print(f"added key {filename} with fingerprint {get_fingerprint(filename)}")

    def change_pw(self, password):
        entries = self._load_shadow()
        pi_user = entries["pi"]

        salt = crypt.mksalt()
        hashed_pw = crypt.crypt(password, salt)

        pi_user["password"] = hashed_pw
        self._save_shadow(entries)

    def _get_shadow_file(self):
        return check_path(self.rootfs / "etc/shadow")

    def _load_shadow(self):
        filename = self._get_shadow_file()
        lines = filename.read_text().splitlines()

        def parse_shadow_line(line):
            values = line.split(":")
            field_names = ["user", "password", "changed", "allowed_change",
                           "required_change", "expiration_warning",
                           "inactive", "expiration", "reserved"]
            result = dict(zip(field_names, values))
            return result["user"], result

        entries = dict([parse_shadow_line(e) for e in lines])
        return entries

    def _save_shadow(self, entries):
        lines = [":".join(x.values()) for x in entries.values()]
        self._get_shadow_file().write_text("\n".join(lines))
        return entries

    def _get_hostname_file(self):
        return check_path(self.rootfs / "etc/hostname")

    def get_hostname(self):
        return self._get_hostname_file().read_text().strip(" \n")

    # https://raspberrypi.stackexchange.com/a/78093
    def change_host(self, hostname):
        # change hostname in etc/hostname
        old_hostname = self.get_hostname()
        self._get_hostname_file().write_text(hostname + "\n")

        # change hostname in etc/hosts
        hosts_file = check_path(self.rootfs / "etc/hosts")
        hosts = hosts_file.read_text()
        hosts = hosts.replace(old_hostname, hostname)
        hosts_file.write_text(hosts)
        print(f"changed hostname from {old_hostname} to {hostname}")

    def configure_ddns(self, web, server, login, password, domain, ipv6=False, interface="eth0"):
        configure(self.rootfs, "etc/ddclient.conf", "ddclient.conf", web=web
                  , server=server, login=login, password=password, domain=domain, )

    def create_cron_job(self, name, what, who="pi", when="@reboot"):
        cron_dir = check_path(self.rootfs / "etc/cron.d")
        cron_file = cron_dir / name
        cron_file.write_text(f"{when} {who} {what}\n")

    def install_ddns(self):
        # setup script to install ddclient on first boot
        source = Path("install_ddns.sh")
        pi_target = Path("home/pi") / source
        target: Path = self.rootfs / pi_target
        shutil.copyfile(source, target)

        self.create_cron_job("install_ddns", f"/bin/bash {str(Path('/') / pi_target)} &")

    def clone_wifi_settings(self):
        ssid = get_current_wifi_ssid()
        psk = get_wifi_psk(ssid)
        self.configure_wifi(ssid, psk)
        print(f"configured pi to use wifi with ssid: {ssid}")

    def configure_serial(self):
        filename = check_path(self.boot / "config.txt")
        set_key_value_config_file(filename=filename, key="dtoverlay", value="pi3-disable-bt", sep="=")
        self.create_cron_job("set_serial_speed", "sudo stty -F /dev/ttyAMA0 speed 1200 crtscts")

        source = Path("configure_serial.sh")
        pi_target = Path("home/pi") / source
        target: Path = self.rootfs / pi_target
        shutil.copyfile(source, target)
        self.create_cron_job("configure_serial", f"/bin/bash {str(Path('/') / pi_target)} &")

    def get_pi_uid(self):
        pi_home = check_path(self.rootfs / "home/pi")
        uid = check_path(pi_home).stat().st_uid
        return uid

    def disable_serial_console(self):
        filename = check_path(self.boot / "cmdline.txt")
        cmdline = filename.read_text()
        cmdline = cmdline.replace("console=serial0,115200", "")
        filename.write_text(cmdline)


def get(dictionary, keys, default=None):
    try:
        for key in keys:
            dictionary = dictionary[key]
    except KeyError:
        return default

    return dictionary


def parse_yaml(configurator, config_file="configuration.yaml"):
    with open(config_file, "r") as f:
        configuration = yaml.safe_load(f)

    if get(configuration, ["ssh", "enable"]) is True:
        configurator.enable_ssh()

    if get(configuration, ["ssh", "key"]):
        configurator.ssh_addkey(get(configuration, ["ssh", "key"]))

    if configuration.get("hostname", False) is True:
        configurator.change_host(configuration["hostname"])

    if configuration.get("wifi", False) is True:
        configurator.clone_wifi_settings()

    if isinstance(configuration.get("wifi", False), list):
        for entry in configuration["wifi"]:
            configurator.configure_wifi(get(entry, ["ssid"]), get(entry, ["ssid"]))

    if configuration.get("static-ip", False):
        configurator.configure_static_ip(ip_address=get(configuration, ["static-ip", "ip"], "192.168.3.14/24")
                                         , interface=get(configuration, ["static-ip", "interface"], "eth0"))

    if configuration.get("password", False):
        configurator.change_pw(configuration["password"])

    if configuration.get("ddns", False):
        configurator.configure_ddns(get(configuration, ["ddns", "web"])
                                    , get(configuration, ["ddns", "server"])
                                    , get(configuration, ["ddns", "login"])
                                    , get(configuration, ["ddns", "password"])
                                    , get(configuration, ["ddns", "domain"])
                                    , get(configuration, ["ddns", "ipv6"], False)
                                    , get(configuration, ["ddns", "interface"], "eth0"))

    if get(configuration, ["serial", "disable-console"]) is True:
        configurator.disable_serial_console()

    if get(configuration, ["serial", "configure"]) is True:
        configurator.configure_serial()


def main():
    card = auto_select_sd_card()
    configurator = PiConfigurator(card)
    parse_yaml(configurator)
    # configurator.enable_ssh()
    # configurator.clone_wifi_settings()
    # configurator.change_host("mir-egal")
    # configure_static_ip(rootfs)
    # enable_ssh(boot)
    # change_host(rootfs, "erika-pi-2")


if __name__ == "__main__":
    gimain()