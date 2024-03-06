import re

import pytest
import responses

from wazuhpy import WazuhClient


base_url = 'https://wazuh_example.com:55000'


class TestWazuhGroupsEndpoints:
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
    def test_groups_endpoint_get_list_of_groups(self, client):
        responses.add(
            responses.GET,
            url=f'{base_url}/groups',
            json={},
            status=200,
        )

        result = client.groups.get()
        assert result.url == f'{base_url}/groups?offset=0&limit=500'

    @responses.activate
    def test_groups_endpoint_get_list_of_groups_agents(self, client):
        responses.add(
            responses.GET,
            re.compile(rf"{base_url}\/groups\/\w*\/agents"),
            json={},
            status=200,
        )

        result = client.groups.agents(group_name='GroupTwo')
        assert result.url == f'{base_url}/groups/GroupTwo/agents?offset=0&limit=500'

    @responses.activate
    def test_groups_endpoint_create_new_group(self, client):
        group_name = 'GroupThree'

        responses.add(
            responses.POST,
            url=f'{base_url}/groups',
            json={'message': f"Group '{group_name}' created.", 'error': 0},
            status=200,
        )

        result = client.groups.create(group_name=group_name).json()

        assert "Group 'GroupThree' created." in result.get('message')

    @responses.activate
    def test_groups_endpoint_get_group_config(self, client):
        group_name = 'GroupTwo'

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/groups\/\w*\/configuration'),
            json={},
            status=200,
        )

        result = client.groups.config(group_name=group_name)
        assert result.url == f'{base_url}/groups/GroupTwo/configuration?offset=0&limit=500'

