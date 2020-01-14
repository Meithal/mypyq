import os
import pathlib
from pprint import pprint as pp
from typing import Tuple, NewType, Dict, Mapping
from logic import utils


ProjectName = NewType('ProjectName', str)
CatName = NewType('CatName', str)
TplName = NewType('TplName', str)
TplCat = NewType('TplCat', Tuple[ProjectName, CatName])
TplKey = NewType('TplKey', Tuple[TplCat, TplName])

tpls: Dict[TplKey, str] = {}


def process_templates(path: pathlib.Path, key: ProjectName):
    for cat in utils.parse_folder(path / 'templates'):
        for tpl in (t for t in cat.iterdir() if t.name.endswith('.html')):
            tpls[TplKey((TplCat((key, CatName(cat.name))), TplName(tpl.stem)))] = open(str(tpl)).read()


def add_project(project):
    process_templates(pathlib.Path('.') / 'projects' / project, project)


def _get_template(cat: TplCat, tpl: TplName) -> str:
    return tpls.get(TplKey((cat, tpl)), "Didn't find any matching template")


def template_text(project: str, cat: str, tpl: str):
    """convenient accessor with generic types"""
    return _get_template(TplCat((ProjectName(project), CatName(cat))), TplName(tpl))


def _recurse_replace(kwargs, domain: TplCat, name):
    recur = _RecurReplacementHandler(kwargs, _get_template(domain, name), domain)
    return _get_template(domain, name).format_map(recur)


class _RecurReplacementHandler(dict):
    site: ProjectName

    def __init__(self, initial_values, content, domain):
        super().__init__(initial_values)

        self.initial_values = initial_values
        self.content = self.trunced = content
        if isinstance(domain, tuple):
            self.site, self.area = domain
        else:
            self.site = ProjectName('global')
            self.area = domain

    def __missing__(self, item):

        if item.startswith("export_"):
            _, domain, name, key = item.split("_")

            self.trunced = self.content.replace(
                "{{export_{domain}_{name}_{key}}}".format(domain=domain, name=name, key=key), ""
            )
            self.initial_values[key] = self.trunced
            self.initial_values['_to_remove'] += len(self.trunced)

            return _recurse_replace(self.initial_values, TplCat((self.site, domain)), name)
        else:
            return "{{{item}}}".format(item=item)

    def __getitem__(self, item):
        if item not in self:
            return self.__missing__(item)
        return "{{{item}}}".format(item=item)


class _FinalReplacerHandler(dict):
    def __missing__(self, key):
        return f"&lt;&lt;&lt;missing {key} >>>"


def parse(domain: TplCat, name: str, **kwargs):
    kwargs['_to_remove'] = 0
    inter = _recurse_replace(kwargs, domain, name)[:-kwargs['_to_remove']]
    final = inter.format_map(_FinalReplacerHandler(kwargs)).format_map(_FinalReplacerHandler(kwargs))
    return final
