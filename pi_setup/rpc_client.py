import subprocess
import xmlrpc.client
from pathlib import Path
import time

if __name__ == '__main__':
    with xmlrpc.client.ServerProxy("http://localhost:8009/") as proxy:
        proxy.touch_user("touched_by_root")
        # Path("testfile_root.txt").touch()
