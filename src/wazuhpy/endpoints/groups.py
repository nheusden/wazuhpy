import json
import requests

from .endpoint import BaseEndpoint


class WazuhGroups(BaseEndpoint):
    def __init__(self, url: str, session: requests.Session, verify_ssl: bool = True):
        super().__init__(url, session, verify_ssl)

    def get(self, pretty: bool = False, wait: bool = False, group_list: list = None,
            offset: int = 0, limit: int = 500, sort: str = None, search: str = None,
            hash: str = None, query: str = None, select: str = None, distinct: bool = False, **kwargs):
        """
        Get information about all groups or a list of them. Returns a list containing
        basic information about each group such as number of agents belonging to the
        group and the checksums of the configuration and shared files

        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param group_list: List of group IDs (separated by comma), all groups selected by default if not specified
        :param offset: First element to return in the collection
        :param limit: Maximum number of elements to return. Although up to 100.000 can be specified, it is
            recommended not to exceed 500 elements. Responses may be slower the more this number is exceeded.
        :param sort: Sort the collection by a field or fields (separated by comma). Use +/- at the beggining
            to list in ascending or descending order. Use '.' for nested fields. For example, '{field1: field2}'
            may be selected with 'field1.field2'
        :param search: Look for elements containing the specified string. To obtain a complementary search, use
            '-' at the beginning
        :param hash: Select algorithm to generate the returned checksums
        :param query: Query to filter results by. For example q="status=active"
        :param select: Select which fields to return (separated by comma). Use '.' for nested fields. For example,
            '{field1: field2}' may be selected with 'field1.field2'
        :param distinct: Look for distinct values.
        :return: Response object
        """
        endpoint = f'{self.url}/groups'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None,
                  'group_list': group_list,
                  'offset': str(offset),
                  'limit': str(limit),
                  'sort': sort,
                  'search': search,
                  'hash': hash,
                  'q': query,
                  'select': select,
                  'distinct': 'True' if distinct else None}

        return self._do(http_method='GET', endpoint=endpoint, params=params, **kwargs)

    def agents(self, group_name: str, pretty: bool = False, wait: bool = False,
               offset: int = 0, limit: int = 500, select: str = None, sort: str = None,
               search: str = None, status: str = None, query: str = None, distinct: bool = False, **kwargs):
        """
        Return the list of agents that belong to the specified group

        :param group_name: Group ID. (Name of the group)
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param offset: First element to return in the collection
        :param limit: Maximum number of elements to return. Although up to 100.000 can be specified, it is
            recommended not to exceed 500 elements. Responses may be slower the more this number is exceeded.
        :param select: Select which fields to return (separated by comma). Use '.' for nested fields. For example,
            '{field1: field2}' may be selected with 'field1.field2'
        :param sort: Sort the collection by a field or fields (separated by comma). Use +/- at the beggining to
            list in ascending or descending order. Use '.' for nested fields. For example, '{field1: field2}' may
            be selected with 'field1.field2'
        :param search: Look for elements containing the specified string. To obtain a complementary search,
            use '-' at the beginning
        :param status: Filter by agent status (use commas to enter multiple statuses)
        :param query: Query to filter results by. For example q="status=active"
        :param distinct: Look for distinct values.
        :return: Response object
        """
        endpoint = f'{self.url}/groups/{group_name}/agents'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None,
                  'offset': str(offset),
                  'limit': str(limit),
                  'select': select,
                  'sort': sort,
                  'search': search,
                  'status': status,
                  'q': query,
                  'distinct': 'True' if distinct else None}

        return self._do(http_method='GET', endpoint=endpoint, params=params, **kwargs)

    def create(self, group_name: str, pretty: bool = False, wait: bool = False, **kwargs):
        """
        Create a new group

        :param group_name: Group name. It can contain any of the characters between
            a-z, A-Z, 0-9, '_', '-' and '.'. Names '.' and '..' are restricted.
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :return: Response Object
        """
        endpoint = f'{self.url}/groups'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None}

        payload = json.dumps({'group_id': group_name})

        return self._do(http_method='POST', endpoint=endpoint, data=payload, params=params, **kwargs)

    def delete(self, groups_list: list, pretty: bool = False, wait: bool = False, **kwargs):
        """
        Delete all groups or a list of them

        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param groups_list: List of group IDs (separated by comma), use the keyword 'all' to select all groups
        :return: Response object
        """
        endpoint = f'{self.url}/groups'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None}

        if groups_list:
            params.update({'groups_list': f"{','.join(groups_list) if groups_list is not None else ''}"})

        return self._do(http_method='DELETE', endpoint=endpoint, params=params, **kwargs)

    def config(self, group_name: str, pretty: bool = False, wait: bool = False,
               offset: int = 0, limit: int = 500, **kwargs):
        """
        Return the group configuration defined in the agent.conf file

        :param group_name: Group ID. (Name of the group)
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param offset: First element to return in the collection
        :param limit: Maximum number of elements to return. Although up to 100.000 can be specified, it is
            recommended not to exceed 500 elements. Responses may be slower the more this number is exceeded.
        :return: Response object
        """
        endpoint = f'{self.url}/groups/{group_name}/configuration'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None,
                  'offset': str(offset),
                  'limit': str(limit)}
        return self._do(http_method='GET', endpoint=endpoint, params=params, **kwargs)