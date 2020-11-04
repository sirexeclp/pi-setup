from xmlrpc.server import SimpleXMLRPCServer
from pathlib import Path
import subprocess


def touch_user(path):
    print(f"touching {path}")
    Path(path).touch()
    return True


if __name__ == '__main__':
    server = SimpleXMLRPCServer(("localhost", 8009))
    print("Listening on port 8009...")
    server.register_function(touch_user, "touch_user")
    server.serve_forever()
