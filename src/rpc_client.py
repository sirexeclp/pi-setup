import xmlrpc.client
from pathlib import Path

with xmlrpc.client.ServerProxy("http://localhost:8009/") as proxy:
    proxy.touch_user()
    Path("testfile_root.txt").touch()