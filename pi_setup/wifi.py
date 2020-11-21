import subprocess
import re
from pathlib import Path


def scan_wifi():
    interface = "wlp1s0"
    regexes = dict(
        frequency="Frequency:(?P<frequency>.*)GHz",
        ssid="ESSID:(?P<ssid>.*)"
    )
    result = subprocess.run(["sudo", "iwlist", interface, "scan"], capture_output=True)
    result_stdout = result.stdout.decode("utf-8")

    wifis = result_stdout.split("Cell")[1:]
    wifi_list = []
    for w in wifis:
        results = {name: re.search(regex, w)[1].strip().strip("\'\"") for name, regex in regexes.items()}
        wifi_list.append(results)

    return wifi_list


def is_ssid_known(ssid):
    network_manager_base_path = Path("/etc/NetworkManager/system-connections")
    con_file = network_manager_base_path / Path(f"{ssid}.nmconnection")
    return con_file.exists()


def filter_by_freq(frequency, target=None):
    if target == "2.4":
        return 2.4 <= float(frequency) < 2.5
    elif target == "5":
        return 5 <= float(frequency) < 6
    else:
        return True


def find_know_networks(frequency_filter=None):
    wifis = scan_wifi()
    known_wifis = [w for w in wifis if is_ssid_known(w["ssid"]) and filter_by_freq(w["frequency"], frequency_filter)]
    return known_wifis




def main():
    # with open("wifi-list.txt", "r") as f:
    #     result_stdout = f.read()
    print(find_know_networks(frequency_filter="2.4"))


if __name__ == '__main__':
    main()
