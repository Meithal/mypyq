import time
import typing

import aiohttp.web as aiow
import aioredis


async def rename_prefix(app: aiow.Application, from_: str, to: str):
    import re

    redis: aioredis.Redis = app['redis']
    async for key in redis.iscan(match=f'{from_}:*'):
        await redis.rename(key, re.sub(from_, to, key.decode('utf8'), count=1))


async def load_redis_resources(app: aiow.Application, key: (str,)):
    redis = app['redis']
    app['resources'][key] = {}

    async for map_key in redis.iscan(match=f'{key}:*'):

        w3map = W3Map.from_redis_haskey(app, map_key)
        async for name, val in redis.ihscan(map_key):
            setattr(w3map, name.decode('utf8'), val.decode('utf8'))
        app['resources']['w3maps'][map_key.decode('utf8')] = w3map
        w3map.after_redis_load()

    print(app['resources']['w3maps'])


class Resource:
    _created_at: int

    def __post_init__(self, *args, **kwargs):
        print("post init called", args, kwargs)
        # if not hasattr(self, 'created_at'):
        #     self.created_at = time.time_ns()

    def __getattribute__(self, item):
        # print("getting", item)
        return object.__getattribute__(self, item)
