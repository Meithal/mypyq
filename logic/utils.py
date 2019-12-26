import os


def clean_parse_folder(name):
    return {*os.listdir(name)} - {'__init__.py', '__pycache__'}
