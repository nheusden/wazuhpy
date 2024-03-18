# Wazuhpy (Under Development)
Wazuhpy is currently under development.

### What is wazuhpy?
> A simple Python API wrapper for the Wazuh API.  Wazuh is an Open Source Security Platform

### Install
`pipenv install git+https://github.com/nheusden/wazuhpy.git`

### Usage

```python
from wazuhpy import WazuhClient

WAZUH_SERVER_URL = 'https://<yourserverurl>:55000'

client = WazuhClient(url=WAZUH_SERVER_URL,
                     username='<username>',
                     password='<password>',
                     verify_ssl=False)

result = client.agents.list(pretty=True, retry=True)
print(result.text)
```

### Examples

##### Agents
List Agents
```python
result = client.agents.list(pretty=True)
print(result.text)
```
Delete devices by id that have a status of either 'disconnected' or 'never_connected' and haven't 
checked in for more than 7 days 
```python
result = client.agents.delete(agents_list=['002', '004', '006'], 
                              status=['disconnected', 'never_connected'],
                              older_than='7d')
```
##### Groups
Create a new group named 'Windows_Devices'
```python
result = client.groups.create(group_name='Windows_Devices')
```
Retrieve basic information about all groups or a list of groups
```python
# get information on all groups
result = client.groups.get(pretty=True)

# specify the groups to retrieve
result = client.groups.get(group_list=['Windows_Devices', 'Test_Group_One'], pretty=True)
```
Get devices in the 'Test_Group_One' group
```python
result = client.groups.agents(group_name='Test_Group_One', pretty=True)
```




