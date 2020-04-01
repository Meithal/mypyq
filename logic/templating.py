import re
import pathlib
import string
from typing import Tuple, NewType, Dict
from logic import utils


ProjectName = NewType('ProjectName', str)
CatName = NewType('CatName', str)
TplName = NewType('TplName', str)
TplKey = NewType('TplKey', Tuple[ProjectName, CatName, TplName])

tpls: Dict[TplKey, str] = {}


def load_files(path: pathlib.Path, key: ProjectName):
    for cat in utils.parse_folder(path / 'templates'):
        for tpl in (t for t in cat.iterdir() if t.name.endswith('.html')):
            tpls[key, CatName(cat.name), TplName(tpl.stem)] = open(str(tpl)).read()
    print(tpls.keys())

class _Catcher(dict):
    has_include: bool = False
    include_into: tuple
    include_key: str

    def __missing__(self, key):
        # print("missing key", key)
        if key.startswith("export_"):
            self.has_include = True
            __, cat, name, keyv = key.split("_")
            self.include_into = cat, name
            self.include_key = keyv
            return ""
        return f"{{{key}}}"


class _InPlace(dict):
    def __missing__(self, key):
        return f"{{{key}}}"


def template_text(project: str, cat: str, tpl: str) -> str:
    """convenient accessor with generic types"""
    return tpls[(project, cat, tpl)]  # _get_template(TplCat((ProjectName(project), CatName(cat))), TplName(tpl))


def add_project(project):
    load_files(pathlib.Path('.') / 'projects' / project, project)

    for key, content in tpls.items():
        catcher = _Catcher()
        text = content.format_map(catcher)
        if catcher.has_include:
            include_into = template_text(project, catcher.include_into[0], catcher.include_into[1])
            # print("include into", include_into)
            tpls[key] = include_into.format_map(_InPlace({catcher.include_key: text}))


def has_template(site, cat, name):
    return (site, cat, name) in tpls


def parse(cat = ('global', 'default'), name = 'index', **data):
    return tpls[cat[0], cat[1], name]


class MyFormatter(string.Formatter):

    def __init__(self, string_):
        self.string = string_

    def format(*args, **kwargs):
        # print(args, kwargs)
        self, *args = args
        return super(MyFormatter, self).format(*args, **kwargs)
        # return format(self.string, args[0])

    # def get_field(self, field_name, args, kwargs):
    #     return self.string

    def get_value(self, key, args, kwargs):
        return self.string


tpl = MyFormatter("test")
# print(tpl.format("test{0}"))

# exit()
