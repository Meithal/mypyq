import os
import logging
import pathlib
import asyncio
import typing
import pprint
import importlib

import sass
from aiohttp import web as aiow

from logic import utils
import templates
import settings

templates.add_project(settings.project)

rp = pathlib.Path('.')

projectPath = rp / 'projects' / settings.project


async def listen_to_sass_changes(app):
    def _compile():
        try:
            sass.compile(dirname=(projectPath / 'scss', rp / '_css'), output_style='expanded')
        except Exception as e:
            print("sass compilation failed", e)

    print("sass listener started")
    _compile()
    sassfiles: typing.Dict[pathlib.Path, os.stat_result] = {
        f: 0
        for f in (projectPath / 'scss').iterdir()
    }
    for f in sassfiles:
        sassfiles[f] = f.stat()
    while True:
        await asyncio.sleep(2.0)
        for f in sassfiles:
            stats = f.stat()
            if sassfiles[f].st_mtime < stats.st_mtime:
                print(f, "has changed, recompiling...")
                _compile()
                sassfiles[f] = stats


async def start_sass_listener(app):
    app['sass_listener'] = asyncio.create_task(listen_to_sass_changes(app))


def is_static_request(request: aiow.Request):
    """Checks if the route capturing the request is a static file handler"""

    return isinstance(request.match_info.route.resource, aiow.StaticResource)


@aiow.middleware
async def add_custom_css(request, handler):
    print(request)
    if not is_static_request(request) and hasattr(request.match_info.route,
                                                  'resource') and request.match_info.route.resource is not None:
        path = request.match_info.route.resource.get_info().get('path', None)

        print(path)

        if path:
            extracss = path[1:]
            if extracss == "":
                extracss = "index"
            request['extra_css'] = f"<link href='_css/{extracss}.css' rel='stylesheet' type='text/css'>"
    resp = await handler(request)
    return resp


routes = aiow.RouteTableDef()


@routes.get('/')
@routes.get('/toto')
async def handle(request):
    print(request)
    name = request.match_info.get('name', "Anonymous")
    extra_css = request.get('extra_css', '')
    return aiow.Response(text=templates.parse(
        (settings.project, 'site'),
        'toto',
        title='Foo',
        foo='bar',
        extra_css=extra_css), headers={'Content-Type': 'text/html'})  # tpls['site']['common'])


routes.static('/_css', rp / '_css')
routes.static('/assets', projectPath / 'assets')



def main():
    middlewares = [add_custom_css]
    print(middlewares)
    app = aiow.Application(middlewares=middlewares)
    app.on_startup.append(start_sass_listener)
    for file in utils.clean_parse_folder(projectPath / 'startup'):
        print('projects.' + settings.project + '.startup.' + str(file).split('.py')[0])
        app.on_startup.append(
            getattr(importlib.import_module('projects.' + settings.project + '.startup.' + str(file).split('.py')[0]),
                    'middleware_reg')
        )

    logging.basicConfig(level=logging.DEBUG)
    app.add_routes(routes)
    aiow.run_app(app)


if __name__ == '__main__':
    main()
