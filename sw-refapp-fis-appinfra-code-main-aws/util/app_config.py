import json

class ApplicationConfig:
    def __init__(self, app_data):
        app_info = app_data.get('app_info', {})
        self._app_names = app_info.get('app_name', [])
        self._app_urls = app_info.get('app_url', [])
        self._subnet_id = app_data.get('subnet_id')
        self._canary_name = app_data.get('canary_name')
        self._az_name = app_data.get('az_name')

    # Getters
    def get_app_names(self):
        return self._app_names
    def get_app_urls(self):
        return self._app_urls
    def get_subnet_id(self):
        return self._subnet_id
    def get_canary_name(self):
        return self._canary_name
    def get_az_name(self):
        return self._az_name

    # Setters
    def set_app_names(self, names):
        self._app_names = names
    def set_app_urls(self, urls):
        self._app_urls = urls
    def set_subnet_id(self, value):
        self._subnet_id = value
    def set_canary_name(self, value):
        self._canary_name = value
    def set_az_name(self, value):
        self._az_name = value