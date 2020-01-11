#! python3 ./dashboard.py
from main import  *
from pathlib import Path
from colorama import init, Fore, Back, Style
init()

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

if __name__ == "__main__":
    card = auto_select_sd_card()
    configurator = PiConfigurator(card)

    hostname = configurator.get_hostname()
    ssh_enabled = configurator.is_ssh_enabled()
    default_pw = configurator.is_default_password()
    static_ip = configurator.get_static_ip()

    print(f"{check_not(hostname,'raspberrypi')} Hostname: {hostname}")
    print(f"{check(ssh_enabled, True)} SSH: {'enabled' if ssh_enabled else 'disabled'}")
    print(f"{check_not(default_pw, True)} Password: {'unchanged' if default_pw else 'changed'}")
    print(f"{check_not(static_ip, None)} Static IP: {static_ip}")