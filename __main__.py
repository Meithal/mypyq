import os
import logging
import pathlib
import asyncio
import typing
import importlib

import sass
from aiohttp import web as aiow

from logic import utils
import templates
import settings

templates.process_templates(pathlib.Path('.'), 'global')
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
    print("scss files", list(sassfiles))
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

        if path:
            extracss = path[1:] or "index"
            request['extra_css_hook'] = f"<link href='_css/{extracss}.css' rel='stylesheet' type='text/css'>"
    resp = await handler(request)
    return resp


@aiow.middleware
async def render_html(request, handler):
    print("render html hook start", request)
    resp = await handler(request)
    # print("resp", resp.text)
    extra_css = request.get('extra_css_hook', '')
    if not is_static_request(request) \
            and hasattr(resp, 'text') \
            and not resp.text.startswith(templates.get_template((settings.project, settings.maincat), 'common')[:5]):
        tplname = request.path[1:]
        resp.text = templates.parse(
            (settings.project, settings.maincat),
            tplname,
            extra_css=extra_css,
            title=f"{settings.project} - {tplname}"
        )

        resp.headers['Content-Type'] = 'text/html'

    # print("resp", resp.text)
    return resp


routes = aiow.RouteTableDef()


@routes.get('/')
async def handle(request):
    print(request)
    extra_css = request.get('extra_css_hook', '')
    return aiow.Response(
        text=templates.parse(
            (settings.project, 'site'),
            'toto',
            title='Foo',
            foo='bar',
            extra_css=extra_css
        ), headers={'Content-Type': 'text/html'}
    )  # tpls['site']['common'])


routes.static('/_css', rp / '_css')
routes.static('/assets', projectPath / 'assets')


def main():
    middlewares = [add_custom_css, render_html]
    print("middlewares", middlewares)
    app = aiow.Application(middlewares=middlewares)
    app['projectPath'] = projectPath
    app.on_startup.append(start_sass_listener)
    for file in utils.parse_folder(projectPath / 'startup'):
        print('projects.' + settings.project + '.startup.' + str(file).split('.py')[0])
        app.on_startup.append(
            getattr(importlib.import_module('projects.' + settings.project + '.startup.' + file.name.split('.py')[0]),
                    'middleware_reg')
        )

        app.on_shutdown.append(
            getattr(importlib.import_module('projects.' + settings.project + '.startup.' + file.name.split('.py')[0]),
                    'on_shutdown')
        )

    logging.basicConfig(level=logging.DEBUG)

    for filename in utils.parse_folder(projectPath / 'controllers'):
        module = importlib.import_module(f"projects.{settings.project}.controllers.{filename.stem}")
        module.View = routes.view(f"/{filename.stem}")(module.View)

    for project in {folder.name for folder in utils.yield_folders(rp / 'projects')} - {settings.project}:
        for filename in utils.parse_folder(rp / 'projects' / project / 'controllers'):
            module = importlib.import_module(f"projects.{project}.controllers.{filename.stem}")
            module.View = routes.view(f"/{project}/{filename.stem}")(module.View)
            templates.add_project(project)

    print("templates", list(templates.tpls))
    print("routes", list(routes))
    app.add_routes(routes)

    import aiohttp_debugtoolbar
    aiohttp_debugtoolbar.setup(app)
    aiow.run_app(app)


if __name__ == '__main__':
    main()
