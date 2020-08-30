import crypt
import json
import re
import shutil
import subprocess
import getpass
from pathlib import Path
import os
import yaml
from git import Repo
import urllib.request
import configparser

DRY_RUN = False


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


def set_key_value_config_file(filename, key, value, sep, unique):
    pair = f"{key}{sep}{value}"
    config = filename.read_text()
    options = config.splitlines()

    regex = re.compile(f"^#?\s*[^\n]{key}{sep}{value if not unique else ''}.*$")
    result = []
    match_found = False
    for line in options:
        if regex.search(line):
            result.append(pair)
            match_found = True
        else:
            result.append(line)

    if not match_found:
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


def get_current_wifi_frequency():
    result = subprocess.run(["iwgetid", "--freq"], capture_output=True)
    regex = ".*Frequency ?:? ?([0-9])\\..*"
    freq = re.match(regex, result.stdout.decode("UTF-8"))[1]
    return int(freq)


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

        username = getpass.getuser()
        assert f"media/{username}/boot" in str(
            self.boot), f"Unexpected mount path of pi boot partition! Expected: /media/{username}/boot Actual: {self.boot}"
        assert f"media/{username}/rootfs" in str(
            self.rootfs), f"Unexpected mount path of pi rootfs partition! Expected: /media/{username}/rootfs Actual: {self.rootfs}"

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
        set_key_value_config_file(filename=self._get_sshd_dir(), key="PasswordAuthentication"
                                  , value="no", sep=" ", unique=True)

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
        os.chown(pi_ssh_dir, self.get_pi_uid(), self.get_pi_gid())
        os.chown(authorized_keys, self.get_pi_uid(), self.get_pi_gid())
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

    def clone_wifi_settings(self, allow_5g):
        if not allow_5g:
            assert get_current_wifi_frequency() == 2, "Current WIFI is on 5GHz, but allow_5g is set to false!"
        ssid = get_current_wifi_ssid()
        psk = get_wifi_psk(ssid)
        self.configure_wifi(ssid, psk)
        print(f"configured pi to use wifi with ssid: {ssid}")

    def _set_boot_config_value(self, key, value, unique):
        filename = check_path(self.boot / "config.txt")
        set_key_value_config_file(filename=filename, key=key, value=value, sep="=", unique=unique)

    def _disable_serial_bt(self):
        self._set_boot_config_value(key="dtoverlay", value="pi3-disable-bt", unique=False)

    def enable_uart(self):
        self._set_boot_config_value(key="enable_uart", value="1", unique=True)

    def apply_ctsrts_device_tree(self):
        device_tree_url = "https://github.com/HiassofT/AtariSIO/raw/master/contrib/rpi/uart-ctsrts.dtbo"
        device_tree_destination = check_path(self.boot / "overlays") / "uart-ctsrts.dtbo"
        urllib.request.urlretrieve(device_tree_url, device_tree_destination)

        self._set_boot_config_value("dtoverlay", "uart-ctsrts", unique=False)

    def configure_serial(self):
        print("disabling bluetooth")
        self._disable_serial_bt()
        print("disabling serial console")
        self.disable_serial_console()
        print("enabling uart")
        self.enable_uart()
        print("applying ctsrts device tree overlay")
        self.apply_ctsrts_device_tree()

        # self.create_cron_job("set_serial_speed", "sudo stty -F /dev/ttyAMA0 speed 1200 crtscts")

        # source = Path("configure_serial.sh")
        # pi_target = Path("home/pi") / source
        # target: Path = self.rootfs / pi_target
        # shutil.copyfile(source, target)
        # self.create_cron_job("configure_serial", f"/bin/bash {str(Path('/') / pi_target)} &")

    def _get_passwd_file(self):
        return check_path(self.rootfs / "etc/passwd")

    def _read_passwd(self):
        passwd = self._get_passwd_file().read_text().splitlines()

        def parse_passwd_line(line):
            values = line.split(":")
            field_names = ["user", "password", "uid", "gid",
                           "info", "home", "shell"]
            result = dict(zip(field_names, values))
            return result["user"], result

        entries = dict([parse_passwd_line(e) for e in passwd])
        return entries

    def _get_group_file(self):
        return check_path(self.rootfs / "etc/group")

    def _read_group(self):
        group = self._get_group_file().read_text().splitlines()

        def parse_group_line(line):
            values = line.split(":")
            field_names = ["group", "password", "gid", "users"]
            result = dict(zip(field_names, values))
            result["users"] = result["users"].split(",")
            return result["group"], result

        entries = dict([parse_group_line(e) for e in group])
        return entries

    def _get_uid(self, user):
        entries = self._read_passwd()
        return int(get(entries, [user, "uid"], None))

    def _get_gid(self, user):
        entries = self._read_passwd()
        return int(get(entries, [user, "gid"], None))

    def get_pi_uid(self):
        return self._get_uid("pi")

    def get_pi_gid(self):
        return self._get_uid("pi")

    def _get_cmdline_file(self):
        return check_path(self.boot / "cmdline.txt")

    def _load_cmdline(self):
        return self._get_cmdline_file().read_text().split(" ")

    def _write_cmdline(self, commands):
        cmdline = " ".join(commands)
        self._get_cmdline_file().write_text(cmdline)

    def disable_serial_console(self):
        regex = re.compile("console=(ttyAMA0|serial0),[0-9]+")

        commands = self._load_cmdline()
        commands = [c for c in commands if regex.search(c) is None]
        self._write_cmdline(commands)

    def git_clone(self, repo, pi_path, user="pi"):
        pi_path = Path(pi_path)

        assert pi_path.is_absolute(), f"pi_path must be an absolute path!"

        target_path = self.rootfs / Path(pi_path).relative_to("/")
        repo = Repo.clone_from(repo, target_path)

        uid = self._get_uid(user)
        gid = self._get_gid(user)

        assert uid is not None, f"No uid found for user {user}!"
        assert gid is not None, f"No uid found for user {user}!"

        chown_recursive(target_path, uid, gid)

        return repo

    def check_user_in_group(self, user, group):
        groups = self._read_group()
        try:
            group = groups[group]
        except KeyError:
            raise Exception(f"Group {group} not found!")
        return user in group["users"]

    def _get_service_definition_file_path(self, service_name):
        definition_path = check_path(self.rootfs / "lib/systemd/system")
        return check_path(definition_path / service_name)

    def _read_service_definition(self, service_name):
        config = configparser.ConfigParser()
        config.read(self._get_service_definition_file_path(service_name))
        return config

    def _get_service_link_path(self, service_name, wanted_by):
        base_path = check_path(self.rootfs / "etc/systemd/system")
        target_path = check_path(base_path / f"{wanted_by}.wants")
        link = target_path / service_name
        return link

    def disable_service(self, service_name):
        config = self._read_service_definition(service_name)
        assert "Install" in config.sections(), f"No install section in {name}!"

        def remove_symlink(wanted_by):
            link = self._get_service_link_path(service_name, wanted_by)
            link.unlink()

        for key, value in config["Install"].items():
            if key == "wantedby":
                remove_symlink(value)
        print(f"Service {service_name} disabled.")

    def enable_service(self, service_name):
        config = self._read_service_definition(service_name)
        assert "Install" in config.sections(), f"No install section in {service_name}!"

        def create_symlink(wanted_by):
            link = self._get_service_link_path(service_name, wanted_by)
            definition_file = self._get_service_definition_file_path(service_name)
            link.symlink_to(definition_file)

        for key, value in config["Install"].items():
            if key == "wantedby":
                create_symlink(value)
        print(f"Service {service_name} enabled.")


def chown_recursive(path, uid, gid):
    os.chown(path, uid, gid)
    for dirpath, dirnames, filenames in os.walk(path):
        for dname in dirnames:
            os.chown(os.path.join(dirpath, dname), uid, gid)
        for fname in filenames:
            os.chown(os.path.join(dirpath, fname), uid, gid)


def get(dictionary, keys, default=None):
    try:
        for key in keys:
            dictionary = dictionary[key]
    except Exception:
        return default

    return dictionary


def parse_yaml(configurator, config_file="configuration.yaml"):
    with open(config_file, "r") as f:
        configuration = yaml.safe_load(f)

    if get(configuration, ["ssh", "enable"]) is True:
        configurator.enable_ssh()

    if get(configuration, ["ssh", "key"]):
        configurator.ssh_addkey(get(configuration, ["ssh", "key"]))

    if configuration.get("hostname", False):
        configurator.change_host(configuration["hostname"])

    if get(configuration, ["wifi", "clone"]) is True:
        configurator.clone_wifi_settings(allow_5g=get(configuration, ["wifi", "allow-5g"], False))

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

    # if get(configuration, ["serial", "disable-console"]) is True:
    #     configurator.disable_serial_console()

    if get(configuration, ["serial", "configure"]) is True:
        configurator.configure_serial()

    if get(configuration, ["git-clone"]):
        configurator.git_clone(get(configuration, ["git-clone", "repo"])
                               , get(configuration, ["git-clone", "path"])
                               , get(configuration, ["git-clone", "user"], "pi"))

    if isinstance(get(configuration, ["service", "disable"]), list):
        for service in get(configuration, ["service", "disable"]):
            configurator.disable_service(service)

    if isinstance(get(configuration, ["service", "enable"]), list):
        for service in get(configuration, ["service", "enable"]):
            configurator.enable_service(service)

def main():
    card = auto_select_sd_card()
    configurator = PiConfigurator(card)
    parse_yaml(configurator)

if __name__ == "__main__":
    main()
