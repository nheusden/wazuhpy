import json
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError

from .endpoints.groups import WazuhGroups
from .endpoints.agents import WazuhAgents
from .endpoints.syscollector import WazuhSyscollector
from .endpoints.vulnerability import WazuhVulnerability

class WazuhClient:
    def __init__(self, url: str = None, username: str = None, password: str = None, verify_ssl: bool = False):
        self.base_url = url
        self.verify_ssl = verify_ssl

        if not verify_ssl:
            requests.packages.urllib3.disable_warnings()

        self.session = requests.Session()

        if username is not None and password is not None:
            _credentials = HTTPBasicAuth(username, password)
            self.authenticate(_credentials)

        # initialize endpoints
        self.groups = WazuhGroups(url=self.base_url, session=self.session, verify_ssl=self.verify_ssl)
        self.agents = WazuhAgents(url=self.base_url, session=self.session, verify_ssl=self.verify_ssl)
        self.syscol = WazuhSyscollector(url=self.base_url, session=self.session, verify_ssl=self.verify_ssl)
        self.vulns = WazuhVulnerability(url=self.base_url, session=self.session, verify_ssl=self.verify_ssl)

    def _update_headers(self, headers: dict):
        return self.session.headers.update(headers)

    def authenticate(self, credentials: HTTPBasicAuth):
        endpoint = f'{self.base_url}/security/user/authenticate'
        try:
            response = self.session.get(url=endpoint, auth=credentials, verify=self.verify_ssl)
            response.raise_for_status()

            if response.status_code == 200:
                json_response = json.loads(response.text)
                if 'token' in json_response.get('data'):
                    headers = {'Authorization': f'Bearer {json_response.get('data')['token']}',
                               'Content-Type': 'application/json'}
                    self._update_headers(headers)
        except HTTPError as err:
            raise