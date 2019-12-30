import os


def clean_parse_folder(name):
    return {*os.listdir(name)} - {'__init__.py', '__pycache__'}


def parse_folder(pathlike):
    for filename in pathlike.iterdir():
        if not filename.stem.startswith('__'):
            yield filename
