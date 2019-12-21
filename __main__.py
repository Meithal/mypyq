import os
import logging
import pathlib
import asyncio
import typing
import pprint

import sass
from aiohttp import web as aiow

import templates

rp = pathlib.Path('.')


async def listen_to_sass_changes(app):
    def _compile():
        try:
            sass.compile(dirname=(rp / 'scss', rp / '_css'), output_style='expanded')
        except Exception as e:
            print("sass compilation failed", e)

    print("sass listener started")
    _compile()
    sassfiles : typing.Dict[pathlib.Path, os.stat_result] = {
        f: 0
        for f in (rp / 'scss').iterdir()
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
    print("add css called", is_static_request(request), request.match_info.route.resource.get_info()) #, pprint.pformat(vars(request)))
    if not is_static_request(request):
        path = request.match_info.route.resource.get_info().get('path', None)
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
    name = request.match_info.get('name', "Anonymous")
    extra_css = request.get('extra_css', '')
    return aiow.Response(text=templates.parse('site', 'toto', title='Foo', foo='bar', extra_css=extra_css), headers={'Content-Type': 'text/html'})  # tpls['site']['common'])

routes.static('/_css', rp / '_css')
routes.static('/assets', rp / 'assets')


def main():
    app = aiow.Application(middlewares=[add_custom_css])
    app.on_startup.append(start_sass_listener)
    logging.basicConfig(level=logging.DEBUG)
    app.add_routes(routes)
    aiow.run_app(app)


if __name__ == '__main__':
    main()
