import aiohttp
import migrate.versioning.api as migrate_api
import pathlib
import os

# print(os.getcwd())

migrate_api.create(pathlib.Path('.') / 'migrations', "Warcraft 3 Vault")
