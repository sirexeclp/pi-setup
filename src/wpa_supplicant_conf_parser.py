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


if __name__ =="__main__":

    cfg_json = config2json(example)
    for network in cfg_json["network"]:
        print(f"- {network['ssid']:<25s} : {network.get('psk', 'None'):10} {network.get('key_mgmt','None')}")
    #print(cfg_json)
    #print("\n".join(json2config(cfg_json)))
    # example = example.replace("=",":")
    # print(example)
    # json.loads(example)