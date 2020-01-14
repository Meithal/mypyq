import os
import inspect
import pprint
import pathlib
import typing


def parse_folder(pathlike: pathlib.Path) -> typing.Iterable[pathlib.Path]:
    for filename in pathlike.iterdir():
        if not filename.stem.startswith('__'):
            yield filename


def yield_folders(pathlike: pathlib.Path) -> typing.Iterable[pathlib.Path]:
    for filename in pathlike.iterdir():
        if filename.is_dir() and not filename.name.startswith('_'):
            yield filename


def trace(*what, **kwargs):
    OBJECT = 0
    FILENAME = 1
    LINENO = 2
    FUNCTION = 3
    CODE_CONTEXT = 4
    INDEX = 5

    depth = kwargs.get('depth', 1)
    prev = None

    print("***Trace/// ===> ", end="")
    for s in inspect.stack()[depth:]:
        # if s[FILENAME].endswith(".py"):
        #     break

        if prev:
            try:
                print(os.path.relpath(s[FILENAME], prev), " - l:", s[LINENO], end=' ')
            except Exception:
                print(s[FILENAME], " - l:", s[LINENO], end=' ')
        else:
            print(s[FILENAME], " - l:", s[LINENO], end=' ')
        prev = s[FILENAME]

    if what:
        print()
        for w in what:
            print("> ", end="")
            pprint.pprint(w)

    print("///>\n")
