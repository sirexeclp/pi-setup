example = """
country=DE 
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev 
update_config=1 
network={
     ssid="F"
     scan_ssid=1
     psk="nyls5422"
     key_mgmt=WPA-PSK
}
network={
     ssid="freifunk-potsdam.de"
     key_mgmt=NONE
}
"""
import json

def json2config(json_config, key = None):
    if isinstance(json_config, str):
        return [f"{key}={json_config}"]
    result = []
    if isinstance(json_config, list):
        for item in json_config:
            result += [f"{key}="]
            result += json2config(item, key)
        return result
    result += ["{"]
    for key, value in json_config.items():
        result += json2config(value,key)
    result +="}"
    return result

    #return "\n".join(result)

if __name__ =="__main__":
    config = {}
    iter = config
    parent = []
    parent.append(iter)
    for line in example.splitlines():
        if line.strip().startswith("#"):
            continue
        if not line.strip():
            continue
        kv_pairs = line.strip().split("=")
        if len(kv_pairs) > 1:# and kv_pairs[1] == "{":
            key = kv_pairs[0]
            value = "=".join(kv_pairs[1:]).strip("\"").strip("\'")
            if value == "{":
                value = {}
            if key in iter:
                old = iter[key]
                if not isinstance(old,list):
                    old = [old]
                iter[key] = old +[value]
            else:
                iter[key] = value

            if isinstance(value, dict):
                parent.append(iter)
                iter = value

        # elif len(kv_pairs) == 2:
        #     iter[kv_pairs[0]] = kv_pairs[1]
        elif "}" in kv_pairs[0]:
            iter = parent.pop()

        print(kv_pairs)
    print(config)
    print("\n".join(json2config(config)))
    # example = example.replace("=",":")
    # print(example)
    # json.loads(example)