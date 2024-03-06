import pytest
import responses

from wazuhpy import WazuhClient


base_url = 'https://wazuh_example.com:55000'


class TestWazuhClient:
    @pytest.fixture()
    @responses.activate
    def client(self):
        responses.add(
            responses.GET,
            url=f'{base_url}/security/user/authenticate',
            json={'data': {'token': 'secret123'}},
            status=200,
        )
        _client = WazuhClient(base_url, 'johndoe', 'secret', verify_ssl=False)
        return _client

    @responses.activate
    def test_token_added_to_header(self, client):
        assert 'Bearer secret123' in client.session.headers.get('Authorization')