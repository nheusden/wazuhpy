import json
import re

import pytest
import responses
from responses import matchers

from wazuhpy import WazuhClient

base_url = 'https://wazuh_example.com:55000'


class TestWazuhSyscollectorEndpoints:
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
    def test_syscollector_endpoint_get_agent_hardware(self, client):
        agent_id = '002'

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/syscollector\/\w+\/hardware'),
            json={},
            status=200,
        )

        result = client.syscol.agent_hardware(agent_id=agent_id, pretty=True)

        assert result.url == f'{base_url}/syscollector/002/hardware?pretty=True'

    @responses.activate
    def test_syscollector_endpoint_get_agent_hotfixes(self, client):
        agent_id = '003'
        hotfix = 'KB2600217'

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/syscollector\/\w+\/hotfixes'),
            json={},
            status=200,
        )

        result = client.syscol.agent_hotfixes(agent_id=agent_id, pretty=True, hotfix=hotfix)
        assert result.url == f'{base_url}/syscollector/003/hotfixes?pretty=True&offset=0&limit=500&hotfix=KB2600217'

    @responses.activate
    def test_syscollector_endpoint_get_agent_netaddr(self, client):
        agent_id = '002'

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/syscollector\/\w*\/netaddr'),
            json={},
            status=200,
        )

        result = client.syscol.agent_netaddr(agent_id=agent_id, pretty=True)
        assert result.url == f'{base_url}/syscollector/002/netaddr?pretty=True&offset=0&limit=500'

    @responses.activate
    def test_syscollector_endpoint_get_agent_netiface(self, client):
        agent_id = '001'
        state = 'up'

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/syscollector\/\w*\/netiface'),
            json={},
            status=200,
        )

        result = client.syscol.agent_netiface(agent_id=agent_id, pretty=True, state=state)

        assert result.url == f'{base_url}/syscollector/{agent_id}/netiface?pretty=True&offset=0&limit=500&state=up'



    @responses.activate
    def test_syscollector_endpoint_get_agent_packages(self, client):

        agent_id = '001'
        vendor = 'Microsoft'
        select = ['scan.id', 'name', 'vendor', 'install_time']

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/syscollector\/\w*\/packages'),
            json={},
            status=200,
        )
        result = client.syscol.agent_packages(agent_id=agent_id, vendor=vendor, select=select)

        assert result.url == (f'{base_url}/syscollector/{agent_id}/packages?offset=0&limit=500&vendor=Microsoft&'
                              f'select=scan.id%2Cname%2Cvendor%2Cinstall_time')
