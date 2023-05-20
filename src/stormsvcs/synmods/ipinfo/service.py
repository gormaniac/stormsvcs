"""Code for the `ipinfo` service."""

import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc

from . import storm


class IPInfoApi(s_cell.CellApi, s_stormsvc.StormSvc):
    '''
    A Telepath API for the ipinfo service.
    '''

    # These defaults must be overridden from the StormSvc mixin
    _storm_svc_name = storm.svc_name
    _storm_svc_vers = storm.svc_vers
    _storm_svc_evts = storm.svc_evts
    _storm_svc_pkgs = storm.svc_pkgs

class IPInfo(s_cell.Cell):

    cellapi = IPInfoApi

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
