"""Code for the `example` service."""

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc

from . import storm


class ExampleApi(s_cell.CellApi, s_stormsvc.StormSvc):
    '''
    A Telepath API for the Example service.
    '''

    # These defaults must be overridden from the StormSvc mixin
    _storm_svc_name = storm.svc_name
    _storm_svc_vers = storm.svc_vers
    _storm_svc_evts = storm.svc_evts
    _storm_svc_pkgs = storm.svc_pkgs

    async def getData(self, query):
        return await self.cell.getData(query)

    async def getInfo(self):
        await self._reqUserAllowed(('example', 'info'))
        return await self.cell.getInfo()

    @s_cell.adminapi()
    async def getAdminInfo(self):
        return await self.cell.getAdminInfo()

class Example(s_cell.Cell):

    cellapi = ExampleApi

    confdefs = {
        'api_key': {
            'type': 'string',
            'description': 'API key for accessing an external service.',
        },
        'api_url': {
            'type': 'string',
            'description': 'The URL for an external service.',
            'default': 'https://example.com',
        },
    }

    async def __anit__(self, dirn, conf):
        await s_cell.Cell.__anit__(self, dirn, conf=conf)
        self.apikey = self.conf.get('api_key')
        self.apiurl = self.conf.get('api_url')

    async def getData(self, query):
        # Best practice is to also return a status and optional message in case of an error
        retn = {
            'status': True,
            'data': None,
            'mesg': None,
        }

        # Retrieving and parsing data would go here
        if query == 'good.com':
            data = ['1.2.3.4', '5.6.7.8']
            retn['data'] = data

        else:
            retn['status'] = False
            retn['mesg'] = 'An error occurred during data retrieval.'

        return retn

    async def getInfo(self):
        info = {
            'generic': 'info',
        }

        return info

    async def getAdminInfo(self):
        info = {
            'admin': 'info',
        }

        return info