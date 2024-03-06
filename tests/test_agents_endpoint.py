import json
import pytest
import re

import responses
from responses import matchers

from wazuhpy import WazuhClient


base_url = 'https://wazuh_example.com:55000'


class TestWazuhAgentsEndpoints:
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
    def test_agents_endpoint_get_agents_list(self, client):

        responses.add(
            responses.GET,
            url=f'{base_url}/agents',
            json={},
            status=200,
        )

        result = client.agents.list()
        assert result.url == f'{base_url}/agents?offset=0&limit=500'

    @responses.activate
    def test_agents_endpoint_filter_agents_by_id_using_agents_list(self, client):

        responses.add(
            responses.GET,
            url=f'{base_url}/agents',
            json={},
            status=200,
        )

        result = client.agents.list(agents_list=['001', '003'])
        assert result.url == f'{base_url}/agents?offset=0&limit=500&agents_list=001%2C003'

    @responses.activate
    def test_agents_endpoint_add_new_agent(self, client):

        new_agent = 'NewAgentOne'

        responses.add(
            responses.POST,
            url=f'{base_url}/agents',
            json={
                "data": {
                    "id": '004', "key": 'ABCD1IFRlc3RBZ2VudFR3byBhbnkgN2M1Ow=='}, "error": 0
                },
            match=[matchers.json_params_matcher({"name": f"{new_agent}"})],
            status=200,
        )

        result = client.agents.add(agent_name='NewAgentOne')

        assert result.json().get('data')['id'] == '004'
        assert result.request.body == json.dumps({'name': new_agent})

    @responses.activate
    def test_agents_endpoint_remove_agent_from_one_or_more_groups(self, client):

        agent_id = '001'

        responses.add(
            responses.DELETE,
            re.compile(rf'{base_url}\/agents\/\w*\/group'),
            json={
                'data': {
                    'affected_items': ['GroupOne'],
                    'total_affected_items': 1,
                    'total_failed_items': 0,
                    'failed_items': []
                }, 'message': 'Specified agent was removed from returned groups', 'error': 0
            },
            status=200,
        )

        result = client.agents.remove_from_groups(agent_id=agent_id, groups_list=['GroupOne'])

        assert result.url == f'{base_url}/agents/{agent_id}/group?groups_list=GroupOne'
        assert result.json().get('data').get('affected_items') == ['GroupOne']
        assert result.request.method == 'DELETE'

    @responses.activate
    def test_agents_endpoint_remove_agent_from_a_single_group(self, client):

        agent_id = '001'
        group_id = 'GroupOne'

        responses.add(
            responses.DELETE,
            re.compile(rf'{base_url}\/agents\/\w*\/group\/\w*'),
            json={
                'message': f"Agent '{agent_id}' removed from '{group_id}'.", 'error': 0
            },
            status=200,
        )

        result = client.agents.remove_from_group(agent_id=agent_id, group_id=group_id)

        assert result.url == f'{base_url}/agents/{agent_id}/group/{group_id}'
        assert result.json().get('message') == f"Agent '{agent_id}' removed from '{group_id}'."

