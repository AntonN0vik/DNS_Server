import json


def get_server_settings() -> dict:
    with open("./config.json", "r") as jsonfile:
        settings = json.load(jsonfile)
    return settings
