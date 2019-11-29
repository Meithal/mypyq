import os
import logging
import pathlib
import asyncio
import typing

import sass
from aiohttp import web as aiow

import templates

rp = pathlib.Path('.')


async def listen_to_sass_changes(app):
    print("sass listener started")
    sassfiles : typing.Dict[pathlib.Path, os.stat_result] = {
        f: 0
        for f in ((rp / 'scss').iterdir())
    }
    for f in sassfiles:
        sassfiles[f] = f.stat()
    #
    while True:
        await asyncio.sleep(2.0)
        for f in sassfiles:
            stats = f.stat()
            if sassfiles[f].st_mtime < stats.st_mtime:
                print(f, "has changed, recompiling...")
                try:
                    sass.compile(dirname=(rp / 'scss', rp / '_css'), output_style='expanded')
                    sassfiles[f] = stats
                except Exception as e:
                    print("sass compilation failed", e)


async def start_sass_listener(app):
    app['sass_listener'] = asyncio.create_task(listen_to_sass_changes(app))

routes = aiow.RouteTableDef()


@routes.get('/')
@routes.get('/toto')
async def handle(request):
    name = request.match_info.get('name', "Anonymous")
    return aiow.Response(text=templates.parse('site', 'toto', title='Foo', foo='bar'), headers={'Content-Type': 'text/html'})  # tpls['site']['common'])


def main():
    app = aiow.Application()
    app.on_startup.append(start_sass_listener)
    logging.basicConfig(level=logging.DEBUG)
    app.add_routes(routes)
    aiow.run_app(app)


if __name__ == '__main__':
    main()
