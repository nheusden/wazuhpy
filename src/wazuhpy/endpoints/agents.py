import json
import requests
from typing import Optional, List
from .endpoint import BaseEndpoint

# todo: write test for delete method
# todo: write test for active_config method

class WazuhAgents(BaseEndpoint):
    def __init__(self, url: str, session: requests.Session, verify_ssl: bool = True):
        super().__init__(url, session, verify_ssl)

    def delete(self, agents_list: List, status: List, pretty: bool = False, wait: bool = False,
               purge: bool = False, older_than: str = None, query: str = None, os_platform: str = None,
               os_version: str = None, os_name: str = None, manager: str = None, version: str = None,
               group: str = None, node_name: str = None, name: str = None, ip_address: str = None,
               register_ip: str = None):
        """
        Delete all agents or a list of them based on optional criteria

        :param agents_list: (required) List of agent ids
        :param status: (required) Filter by List of agent statuses
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param purge: Permanently delete an agent from the key store
        :param older_than: Consider only agents whose last keep alive is older than the specified timeframe.
            For never_connected agents, register date is considered instead of last keep alive.
            For example, 7d, 10s, 10 are valid values. When no time unit is specified, seconds
            are assumed.  Use 0s to select all agents.
        :param query: Query to filter results by. For example q="status=active"
        :param os_platform: Filter by OS platform
        :param os_version: Filter by OS version
        :param os_name: Filter by OS name
        :param manager: Filter by manager hostname where agents are connected to
        :param version: Filter by agents version using one of the following formats: 'X.Y.Z', 'vX.Y.Z',
            'wazuh X.Y.Z' or 'wazuh vX.Y.Z'. For example: '4.4.0'
        :param group: Filter by group of agents
        :param node_name: Filter by node name
        :param name: Filter by name
        :param ip_address: Filter by the IP used by the agent to communicate with the manager.
            If it's not available, it will have the same value as registerIP
        :param register_ip: Filter by the IP used when registering the agent
        :return: Response object
        """
        endpoint = f'{self.url}/agents'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None,
                  'purge': 'True' if purge else None,
                  'older_than': older_than,
                  'q': query,
                  'os.platform': os_platform,
                  'os.version': os_version,
                  'os.name': os_name,
                  'manager': manager,
                  'version': version,
                  'group': group,
                  'node_name': node_name,
                  'ip': ip_address,
                  'registerIP': register_ip}

        if not agents_list or not status:
            raise Exception('agent_list and status are required')
        else:
            params.update({'agents_list': f"{','.join(agents_list) if agents_list is not None else ''}",
                           'status': f"{','.join(status) if status is not None else ''}"})

        return self._do(http_method='DELETE', endpoint=endpoint, params=params)

    def list(self, pretty: bool = False, wait: bool = False, agents_list: List = None,
             offset: int = 0, limit: int = 500, select: List = None, sort: str = None,
             search: str = None, status: List = None, query: str = None, older_than: str = None,
             os_platform: str = None, os_version: str = None, os_name: str = None, manager: str = None,
             version: str = None, group: str = None, node_name: str = None, name: str = None,
             ip_address: str = None, register_ip: str = None, group_config_status: str = None,
             distinct: bool = False):
        """
        Return information about all available agents or a list of them

        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param agents_list: List of agent IDs
        :param offset: First element to return in the collection (Default: 0)
        :param limit: Maximum number of elements to return. Although up to 100.000 can be specified,
            it is recommended not to exceed 500 elements. Responses may be slower the more this number is exceeded.
            (Default: 500)
        :param select: Select which fields to return. Use '.' for nested fields.
            For example, '{field1: field2}' may be selected with 'field1.field2'
        :param sort: Sort the collection by a field or fields. Use +/- at the beggining to list in ascending or
            descending order. Use '.' for nested fields. For example, '{field1: field2}' may be selected with
            'field1.field2
        :param search: Look for elements containing the specified string. To obtain a complementary search,
            use '-' at the beginning
        :param status: Filter by agent status
        :param query: Query to filter results by. For example q="status=active"
        :param older_than: Filter out agents whose time lapse from last keep alive signal is longer than specified.
            Time in seconds, ‘[n_days]d’, ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never_connected agents,
            uses the register date. For example, 7d, 10s and 10 are valid values. If no time unit is specified,
            seconds are used
        :param os_platform: Filter by OS platform
        :param os_version: Filter by OS version
        :param os_name: Filter by OS name
        :param manager: Filter by manager hostname where agents are connected to
        :param version: Filter by agents version using one of the following formats: 'X.Y.Z', 'vX.Y.Z', 'wazuh X.Y.Z'
            or 'wazuh vX.Y.Z'. For example: '4.4.0
        :param group: Filter by group of agents
        :param node_name: Filter by node name
        :param name: Filter by name
        :param ip_address: Filter by the IP used by the agent to communicate with the manager. If it's not available,
            it will have the same value as registerIP
        :param register_ip: Filter by the IP used when registering the agent
        :param group_config_status: Agent groups configuration sync status
        :param distinct: Look for distinct values
        :return: Response object
        """
        endpoint = f'{self.url}/agents'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None,
                  'offset': str(offset),
                  'limit': str(limit),
                  'sort': sort,
                  'search': search,
                  'q': query,
                  'older_than': older_than,
                  'os.platform': os_platform,
                  'os.version': os_version,
                  'os.name': os_name,
                  'manager': manager,
                  'version': version,
                  'group': group,
                  'node_name': node_name,
                  'name': name,
                  'ip': ip_address,
                  'registerIP': register_ip,
                  'group_config_status': group_config_status,
                  'distinct': 'True' if distinct else None}

        if agents_list:
            # agents_list=['001', '002'] returns the two selected agents
            params.update({'agents_list': f"{','.join(agents_list) if agents_list is not None else ''}"})

        if select:
            # select=['id', 'os.name', 'os.platform', 'os.arch'] returns the specified fields
            params.update({'select': f"{','.join(select) if select is not None else ''}"})

        if status:
            params.update({'status': f"{','.join(status) if status is not None else ''}"})

        return self._do(http_method='GET', endpoint=endpoint, params=params)

    def add(self, agent_name: str, ip_address: Optional[str] = None, pretty: bool = False, wait: bool = False):
        """
         Add a new agent

        :param agent_name: (required) Agent name
        :param ip_address: If this is not included, the API will get the IP automatically.
            Allowed values: IP, IP/NET, ANY
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :return: Response object
        """
        endpoint = f'{self.url}/agents'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None}

        data = {'name': agent_name}
        if ip_address:
            data.update({'ip': ip_address})

        payload = json.dumps(data)

        return self._do(http_method='POST', endpoint=endpoint, data=payload, params=params)

    def active_config(self, agent_id: str, component: str,
                      configuration: str, pretty: bool = False, wait: bool = False):
        """
        Return the active configuration the agent is currently using. This can be different from the configuration
        present in the configuration file, if it has been modified and the agent has not been restarted yet

        :param agent_id: Agent ID. All possible values from 000 onwards
        :param component: Selected agent's component
        :param configuration: Selected agent's configuration to read. The configuration to read depends
            on the selected component.
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :return: Response object
        """

        endpoint = f'{self.url}/agents/{agent_id}/config/{component}/{configuration}'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None}

        return self._do(http_method='GET', endpoint=endpoint, params=params)

    def remove_from_group(self, agent_id: str, group_id: str, pretty: bool = False, wait: bool = False):
        """
        Remove an agent from a specified group. If the agent belongs to several groups,
        only the specified group will be deleted.

        :param agent_id: (required) Agent ID. All possible values from 000 onwards
        :param group_id: (required) Group ID. (Name of the group)
        :param pretty: Show results in human-readable forma
        :param wait: Disable timeout response
        :return: Response object
        """
        endpoint = f'{self.url}/agents/{agent_id}/group/{group_id}'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None}

        return self._do(http_method='DELETE', endpoint=endpoint, params=params)

    def remove_from_groups(self, agent_id: str, pretty: bool = False,
                          wait: bool = False, groups_list: List = None):
        """
        Remove the agent from all groups or a list of them. The agent will
        automatically revert to the default group if it is removed from all its assigned groups

        :param agent_id: (required) Agent ID. All possible values from 000 onwards
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param groups_list: List of group IDs, all groups selected by default if not specified
        :return: Response object
        """
        endpoint = f'{self.url}/agents/{agent_id}/group'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None,
                  'groups_list': f"{','.join(groups_list) if groups_list else None}"}

        return self._do(http_method='DELETE', endpoint=endpoint, params=params)
