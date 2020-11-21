#! python3 ./dashboard.py
import time

from pi_setup.sd_card import DeviceManager, select_sd_card
from pi_setup.pi_setup import *
from pathlib import Path
from colorama import init, Fore, Back, Style

from pi_setup.wpa_supplicant_conf_parser import list_networks

init()


def check(value, condition, is_not=False):
    if value == condition:
        return f"{Fore.GREEN}✔{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}✘{Style.RESET_ALL}"


def check_not(value, condition):
    if value != condition:
        return f"{Fore.GREEN}✔{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}✘{Style.RESET_ALL}"


def main():
    cards = DeviceManager.get_sd_cards()
    card = select_sd_card(cards)
    with card:
        time.sleep(1)

        print("----")
        configurator = PiConfigurator(card)

        hostname = configurator.get_hostname()
        ssh_enabled = configurator.is_ssh_enabled()
        default_pw = configurator.is_default_password()
        static_ip = configurator.get_static_ip()
        is_group_dialout = configurator.check_user_in_group("pi", "dialout")

        print(f"{check_not(hostname, 'raspberrypi')} Hostname: {hostname}")
        print(f"{check(ssh_enabled, True)} SSH: {'enabled' if ssh_enabled else 'disabled'}")
        print(f"{check_not(default_pw, True)} Password: {'unchanged' if default_pw else 'changed'}")
        print(f"{check_not(static_ip, None)} Static IP: {static_ip}")
        print(f"{check(is_group_dialout, True)} User pi is"
              f"{' ' if is_group_dialout else ' not '}a member of the group dialout.")

        print(list_networks(configurator.rootfs))


if __name__ == "__main__":
    main()
