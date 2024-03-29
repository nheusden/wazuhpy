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
    def test_agents_endpoint_delete_agent(self, client):
        agents_list = ['003', '004']
        status = ['disconnected', 'never_connected']

        responses.add(
            responses.DELETE,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=200,
        )
        result = client.agents.delete(agents_list=agents_list, status=status, older_than='1h')
        assert result.url == (f'{base_url}/agents?older_than=1h&agents_list=003%2C004&'
                              f'status=disconnected%2Cnever_connected')
        assert result.request.method == 'DELETE'

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

    @responses.activate
    def test_agents_endpoint_distinct(self, client):

        fields = ['name', 'os.name', 'status', 'group']

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents\/stats\/distinct'),
            json={},
            status=200,
        )

        result = client.agents.distinct(fields=fields, pretty=True)

        assert result.url == (f'{base_url}/agents/stats/distinct?pretty=True&'
                              f'offset=0&limit=500&fields=name%2Cos.name%2Cstatus%2Cgroup')

    @responses.activate
    def test_agents_endpoint_active_config(self, client):
        agent_id = '003'
        component = 'agent'
        configuration = 'labels'

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents\/\w*\/config\/\w*\/\w*'),
            json={},
            status=200,
        )

        result = client.agents.active_config(agent_id=agent_id,
                                             component=component,
                                             configuration=configuration,
                                             pretty=True)

        assert result.url == f'{base_url}/agents/{agent_id}/config/{component}/{configuration}?pretty=True'

    @responses.activate
    def test_agents_endpoint_get_agent_list_with_retry_as_instance_of_retry(self, client):
        from requests.adapters import Retry

        retry = Retry(total=10,
                      backoff_factor=0.1,
                      status_forcelist=[500, 502, 503, 504])
        
        agents_list = ['001', '003']

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=500,
            match=[matchers.request_kwargs_matcher({'retry': Retry(total=5)})],
        )

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=502,
        )

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=503,
        )

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=504,
        )

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=200,
        )

        result = client.agents.list(agents_list=['001', '003'], retry=retry)
        assert responses.assert_call_count(f'{base_url}/agents?offset=0&limit=500&agents_list=001%2C003', 4)

    @responses.activate
    def test_agents_endpoint_get_agent_list_with_retry_as_bool(self, client):
        from requests.adapters import Retry

        agents_list = ['001', '003', '002']

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=500,
            match=[matchers.request_kwargs_matcher({'retry': Retry(total=5)})],
        )

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=502,
        )

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=503,
        )

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=504,
        )

        responses.add(
            responses.GET,
            re.compile(rf'{base_url}\/agents'),
            json={},
            status=200,
        )

        result = client.agents.list(agents_list=agents_list, retry=True)
        assert responses.assert_call_count(f'{base_url}/agents?offset=0&limit=500&agents_list=001%2C003%2C002', 4)


        

