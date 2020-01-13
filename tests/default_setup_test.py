import pytest
import keyring
from main import *


def test_default_setup_test():
    # if os.geteuid() != 0:
    #     subprocess.call(['sudo', 'python3', *sys.argv])
    #     sys.exit()

    devices = lsblk()
    cards = filter_sd_cards(devices)
    assert len(cards) == 1, "Error: more than one sd card found"
    # print(cards)
    boot = get_mounts(cards[0], "boot")[0]
    rootfs = get_mounts(cards[0], "rootfs")[0]
    assert boot == "/media/felix/boot", "unexpected mount path of pi boot partition"
    assert rootfs == "/media/felix/rootfs", "unexpected mount path of pi rootfs partition"
    print(f"boot: {boot}")
    print(f"rootfs: {rootfs}")

    # enable_ssh(boot)
    # add2wifi(boot)
    # # # configure_static_ip(root_fs)
    # pub_key = ssh_keygen("test123", "")
    # ssh_addkey(root_fs, pub_key)
    # # disable_password_authentication()
    # change_pw(root_fs, "test")
    # hostname = "testpi"
    # change_host(root_fs, hostname)
    # # setup ddclient config file
    # install_ddns(root_fs)
    # domain = "erika2.nerdpol.ovh"
    # server = "ipv4.nsupdate.info"
    # configure_ddns(root_fs, web=server+"/myip"
    #           , server=server, login=domain, password=keyring.get_password(domain, domain),
    #           domain=domain, ipv6=True)

    # add2ssh_conf(hostname, hostname, pub_key)