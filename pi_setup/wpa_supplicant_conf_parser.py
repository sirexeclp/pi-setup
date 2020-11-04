from pathlib import Path

example = """
country=DE 
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev 
update_config=1 
# This is a comment
network={
     ssid="F"
     scan_ssid=1
     psk="nyls5422"
     key_mgmt=WPA-PSK
}
network={
# insider comment
     ssid="freifunk-potsdam.de"
     key_mgmt=NONE
}
"""
import json

def json2config(json_config, key = None ,indent=0):
    if isinstance(json_config, str):
        if key.startswith("#"):
            return [f"{' '*4*indent}#{json_config}"]
        else:
            return [f"{' '*4*indent}{key}={json_config}"]
    result = []
    if isinstance(json_config, list):
        for item in json_config:
            result += [f"{key}={{"]
            result += json2config(item, key, indent=indent+1)
            result += ["}"]
        return result
    # result += ["{"]
    for key, value in json_config.items():
        result += json2config(value, key, indent=indent)
    # result +="}"
    return result

    #return "\n".join(result)

def config2json(config):
    result = {}
    in_block = False
    parent = None
    comment_counter = 0
    for line in config.splitlines():
        line = line.strip()

        if "=" in line:
            key, value = line.strip().split("=", maxsplit=1)
            if value == "{":
                in_block = True
                child = {}
                if key in result:
                    if isinstance(result[key], list):
                        result[key].append(child)
                    else:
                        result[key] = [result[key], child]
                else:
                    result[key] = child
                parent = result
                result = child
            else:
                #value = value#.strip("\"").strip("\'")
                result[key] = value
        elif line == "}":
            in_block = False
            result = parent

        if line.strip().startswith("#"):
            result[f"#{comment_counter}"] = line.strip()[1:]
        if not line.strip():
            continue

    return result


def always_iterable(obj, base_type=(str, bytes)):
    """If *obj* is iterable, return an iterator over its items::
        >>> obj = (1, 2, 3)
        >>> list(always_iterable(obj))
        [1, 2, 3]
    If *obj* is not iterable, return a one-item iterable containing *obj*::
        >>> obj = 1
        >>> list(always_iterable(obj))
        [1]
    If *obj* is ``None``, return an empty iterable:
        >>> obj = None
        >>> list(always_iterable(None))
        []
    By default, binary and text strings are not considered iterable::
        >>> obj = 'foo'
        >>> list(always_iterable(obj))
        ['foo']
    If *base_type* is set, objects for which ``isinstance(obj, base_type)``
    returns ``True`` won't be considered iterable.
        >>> obj = {'a': 1}
        >>> list(always_iterable(obj))  # Iterate over the dict's keys
        ['a']
        >>> list(always_iterable(obj, base_type=dict))  # Treat dicts as a unit
        [{'a': 1}]
    Set *base_type* to ``None`` to avoid any special handling and treat objects
    Python considers iterable as iterable:
        >>> obj = 'foo'
        >>> list(always_iterable(obj, base_type=None))
        ['f', 'o', 'o']
    """
    if obj is None:
        return iter(())

    if (base_type is not None) and isinstance(obj, base_type):
        return iter((obj,))

    try:
        return iter(obj)
    except TypeError:
        return iter((obj,))


def print_networks(cfg_json):
    if not isinstance(cfg_json["network"], list):
        cfg_json["network"] = [cfg_json["network"]]

    for network in always_iterable(cfg_json["network"], base_type=dict):
        print(f"- {network['ssid']:<25s} : {network.get('psk', 'None'):10} {network.get('key_mgmt','None')}")


def list_networks(root_path):
    # root_path = Path(root_path)
    wpa_path = root_path / "etc/wpa_supplicant/wpa_supplicant.conf"
    wpa_content = wpa_path.read_text()
    wpa_json = config2json(wpa_content)
    print_networks(wpa_json)


if __name__ =="__main__":

    cfg_json = config2json(example)
    print_networks(cfg_json)

    #print(cfg_json)
    #print("\n".join(json2config(cfg_json)))
    # example = example.replace("=",":")
    # print(example)
    # json.loads(example)
