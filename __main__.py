import logging

from aiohttp import web as aiow

import templates

routes = aiow.RouteTableDef()


@routes.get('/')
async def handle(request):
    name = request.match_info.get('name', "Anonymous")
    text = "Hello, " + name
    return aiow.Response(text=templates.parse('site', 'toto', title='Foo', foo='bar'))  # tpls['site']['common'])


def main():
    app = aiow.Application()
    logging.basicConfig(level=logging.DEBUG)
    app.add_routes(routes)
    aiow.run_app(app)


if __name__ == '__main__':
    main()
