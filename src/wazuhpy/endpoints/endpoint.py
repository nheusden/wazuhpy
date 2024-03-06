import requests

from typing import Optional, Dict

from requests.exceptions import HTTPError


class BaseEndpoint:
    """Class for handling requests"""
    def __init__(self, url: str, session: requests.Session = None, verify_ssl: bool = True):
        self.url = url
        self.verify_ssl = verify_ssl
        self.session = session

    def _do(self, http_method: str, endpoint: str, params: Dict = None,
            data=None, files: Dict = None, **kwargs):
        try:
            response = self.session.request(method=http_method, url=endpoint, params=params,
                                            data=data, files=files, verify=self.verify_ssl, **kwargs)
            response.raise_for_status()
            return response

        except HTTPError as err:
            raise