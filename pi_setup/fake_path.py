from pathlib import Path
from typing import Optional


class FakePath:

    def __init__(self, *args, **kwargs):
        self._path = Path(*args, **kwargs)

    def write_text(self, data: str, encoding: Optional[str] = None,
                       errors: Optional[str] = None) -> int:
        print(data)

    def __truediv__(self, other):
        self._path = self._path / other
        return self

    def __str__(self):
        return str(self._path)

if __name__ == '__main__':
    test = FakePath("test_file.txt")
    test = test / "hahaha"
    test.write_text("TRololololo!")
    print(str(test))
