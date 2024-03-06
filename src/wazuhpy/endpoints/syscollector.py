import json
import requests
from typing import Optional, List
from .endpoint import BaseEndpoint


class WazuhSyscollector(BaseEndpoint):
    def __init__(self, url: str, session: requests.Session, verify_ssl: bool = True):
        super().__init__(url, session, verify_ssl)

    def agent_hardware(self, agent_id: str, pretty: bool = False, wait: bool = False,
                       select: list = None):
        """
        Return the agent's hardware info. This information include cpu, ram, scan info among others

        :param agent_id: Agent ID. All possible values from 000 onwards
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param select: Select which fields to return (separated by comma). Use '.' for nested fields. For example,
            '{field1: field2}' may be selected with 'field1.field2'
        :return: Response object
        """
        endpoint = f'{self.url}/syscollector/{agent_id}/hardware'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None}

        if select:
            params.update({'select': f"{','.join(select) if select is not None else ''}"})

        return self._do(http_method='GET', endpoint=endpoint, params=params)

    def agent_hotfixes(self, agent_id: str, pretty: bool = False, wait: bool = False,
                       offset: int = 0, limit: int = 500, sort: str = None, search: str = None,
                       select: list = None, hotfix: str = None, query: str = None, distinct: bool = False):
        """
        Return all hotfixes installed by Microsoft(R) in Windows(R) systems

        :param agent_id: Agent ID. All possible values from 000 onwards
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param offset: First element to return in the collection (Default: 0)
        :param limit: Maximum number of elements to return. Although up to 100.000 can be specified, it is
            recommended not to exceed 500 elements. Responses may be slower the more this number is exceeded.
            (Default: 500)
        :param sort: Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
            to list in ascending or descending order. Use '.' for nested fields. For example, '{field1: field2}'
            may be selected with 'field1.field2'
        :param search: Look for elements containing the specified string. To obtain a complementary search, use
            '-' at the beginning
        :param select: Select which fields to return (separated by comma). Use '.' for nested fields. For example,
            '{field1: field2}' may be selected with 'field1.field2'
        :param hotfix: Filter by hotfix
        :param query: Query to filter results by. For example q="status=active"
        :param distinct: Look for distinct values
        :return: Response object
        """
        endpoint = f'{self.url}/syscollector/{agent_id}/hotfixes'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None,
                  'offset': str(offset),
                  'limit': str(limit),
                  'sort': sort,
                  'search': search,
                  'hotfix': hotfix,
                  'q': query,
                  'distinct': 'True' if distinct else None}

        if select:
            params.update({'select': f"{','.join(select) if select is not None else ''}"})

        return self._do(http_method='GET', endpoint=endpoint, params=params)

    def agent_netaddr(self, agent_id: str, pretty: bool = False, wait: bool = False,
                      offset: int = 0, limit: int = 500, sort: str = None, search: str = None,
                      select: list = None, iface: str = None, proto: str = None, address: str = None,
                      broadcast: str = None, netmask: str = None, query: str = None, distinct: bool = False):
        """
        Return the agent's network address info. This information include used IP protocol,
        interface, IP address among others

        :param agent_id: Agent ID. All possible values from 000 onwards
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param offset: First element to return in the collection
        :param limit: Maximum number of elements to return. Although up to 100.000 can be specified, it is
            recommended not to exceed 500 elements. Responses may be slower the more this number is exceeded.
        :param sort: Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
            to list in ascending or descending order. Use '.' for nested fields. For example, '{field1: field2}'
            may be selected with 'field1.field2'
        :param search: Look for elements containing the specified string. To obtain a complementary search,
            use '-' at the beginning
        :param select: Select which fields to return (separated by comma). Use '.' for nested fields. For
            example, '{field1: field2}' may be selected with 'field1.field2'
        :param iface: Filter by network interface
        :param proto: Filter by IP protocol
        :param address: Filter by IP address
        :param broadcast: Filter by broadcast direction
        :param netmask: Filter by netmask
        :param query: Query to filter results by. For example q="status=active"
        :param distinct: Look for distinct values.
        :return: Response object
        """
        endpoint = f'{self.url}/syscollector/{agent_id}/netaddr'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None,
                  'offset': str(offset),
                  'limit': str(limit),
                  'sort': sort,
                  'search': search,
                  'iface': iface,
                  'proto': proto,
                  'address': address,
                  'broadcast': broadcast,
                  'netmask': netmask,
                  'q': query,
                  'distinct': 'True' if distinct else None}

        if select:
            params.update({'select': f"{','.join(select) if select is not None else ''}"})

        return self._do(http_method='GET', endpoint=endpoint, params=params)

    def agent_netiface(self, agent_id: str, pretty: bool = False, wait: bool = False,
                       offset: int = 0, limit: int = 500, sort: str = None, search: str = None,
                       select: list = None, name: str = None, adapter: str = None, type: str = None,
                       state: str = None, mtu: int = None, tx_packets: int = None, rx_packets: int = None,
                       tx_bytes: int = None, rx_bytes: int = None, tx_errors: int = None, rx_errors: int = None,
                       tx_dropped: int = None, rx_dropped: int = None, query: str = None, distinct: bool = False):
        """
        Return the agent's network interface info. This information include rx, scan, tx info and some network
        information among others

        :param agent_id: Agent ID. All possible values from 000 onwards
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param offset: First element to return in the collection (Default: 0)
        :param limit: Maximum number of elements to return. Although up to 100.000 can be specified, it is
            recommended not to exceed 500 elements. Responses may be slower the more this number is exceeded.
            (Default: 500)
        :param sort: Sort the collection by a field or fields (separated by comma). Use +/- at the beggining
            to list in ascending or descending order. Use '.' for nested fields. For example, '{field1: field2}'
            may be selected with 'field1.field2'
        :param search: Look for elements containing the specified string. To obtain a complementary search,
            use '-' at the beginning
        :param select: Select which fields to return (separated by comma). Use '.' for nested fields. For example,
            '{field1: field2}' may be selected with 'field1.field2'
        :param name: Filter by name
        :param adapter: Filter by adapter
        :param type: Type of interface
        :param state: Filter by state
        :param mtu: Filter by mtu
        :param tx_packets: Filter by tx.packets
        :param rx_packets: Filter by rx.packets
        :param tx_bytes: Filter by tx.bytes
        :param rx_bytes: Filter by rx.bytes
        :param tx_errors: Filter by tx.errors
        :param rx_errors: Filter by rx.errors
        :param tx_dropped: Filter by tx.dropped
        :param rx_dropped: Filter by rx.dropped
        :param query: Query to filter results by. For example q="status=active"
        :param distinct: Look for distinct values.
        :return: Response object
        """
        endpoint = f'{self.url}/syscollector/{agent_id}/netiface'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None,
                  'offset': str(offset),
                  'limit': str(limit),
                  'sort': sort,
                  'search': search,
                  'name': name,
                  'adapter': adapter,
                  'type': type,
                  'state': state,
                  'mtu': str(mtu) if mtu else None,
                  'tx.packets': str(tx_packets) if tx_packets else None,
                  'rx.packets': str(rx_packets) if rx_packets else None,
                  'tx.bytes': str(tx_bytes) if tx_bytes else None,
                  'rx.bytes': str(rx_bytes) if rx_bytes else None,
                  'tx.errors': str(tx_errors) if tx_errors else None,
                  'rx.errors': str(rx_errors) if rx_errors else None,
                  'tx.dropped': str(tx_dropped) if tx_dropped else None,
                  'rx.dropped': str(rx_dropped) if rx_dropped else None,
                  'q': query,
                  'distinct': 'True' if distinct else None}

        if select:
            params.update({'select': f"{','.join(select) if select is not None else ''}"})

        return self._do(http_method='GET', endpoint=endpoint, params=params)

    def agent_netproto(self):
        pass

    def agent_os(self):
        pass

    def agent_packages(self, agent_id: str, pretty: bool = False, wait: bool = False,
                           offset: int = 0, limit: int = 500, sort: str = None, search: str = None,
                           select: List = None, vendor: str = None, name: str = None, architecture: str = None,
                           format: str = None, version: str = None, query: str = None, distinct: bool = False):
        """
        Return the agent's packages info. This information include name, section, size,
        priority information of all packages among others

        :param agent_id: Agent ID. All possible values from 000 onwards
        :param pretty: Show results in human-readable format
        :param wait: Disable timeout response
        :param offset: First element to return in the collection (Default: 0)
        :param limit: Maximum number of elements to return. Although up to 100.000 can be specified, it is
            recommended not to exceed 500 elements. Responses may be slower the more this number is exceeded.
            (Default: 500)
        :param sort: Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
            to list in ascending or descending order. Use '.' for nested fields. For example, '{field1: field2}'
            may be selected with 'field1.field2'
        :param search: Look for elements containing the specified string. To obtain a complementary search,
            use '-' at the beginning
        :param select: Select which fields to return (separated by comma). Use '.' for nested fields. For example,
            '{field1: field2}' may be selected with 'field1.field2'
        :param vendor: Filter by vendor
        :param name: Filter by name
        :param architecture: Filter by architecture
        :param format: Filter by file format. For example 'deb' will output deb files
        :param version: Filter by package version
        :param query: Query to filter results by. For example q="status=active"
        :param distinct: Look for distinct values.
        :return: Response object
        """
        endpoint = f'{self.url}/syscollector/{agent_id}/packages'

        params = {'pretty': 'True' if pretty else None,
                  'wait_for_complete': 'True' if wait else None,
                  'offset': str(offset),
                  'limit': str(limit),
                  'sort': sort,
                  'search': search,
                  'vendor': vendor,
                  'name': name,
                  'architecture': architecture,
                  'format': format,
                  'version': version,
                  'q': query,
                  'distinct': 'True' if distinct else None}

        if select:
            params.update({'select': f"{','.join(select) if select is not None else ''}"})

        return self._do(http_method='GET', endpoint=endpoint, params=params)

    def agent_ports(self):
        pass

    def agent_processes(self):
        pass