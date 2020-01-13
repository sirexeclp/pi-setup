from xmlrpc.server import SimpleXMLRPCServer
from pathlib import Path
import subprocess

def touch_user():
    Path("test_file.txt").touch()
    return True

subprocess.Popen(["sudo", "python3", "./rpc_client.py"])

server = SimpleXMLRPCServer(("localhost", 8009))
print("Listening on port 8009...")
server.register_function(touch_user, "touch_user")
server.serve_forever()