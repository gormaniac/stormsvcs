"""Storm definitions for the `ipinfo` command."""

from .version import svc_vers, svc_minvers

# Other Storm commands could be created to call the additional Telepath endpoints.
svc_name = 'example'
svc_guid = '0ecc1eb65659a0f07141bc1a360abda3'  # can be generated with synapse.common.guid()

svc_evts = {
    'add': {
        'storm': f'[(meta:source={svc_guid} :name="Example data")]'
    }
}

svc_mod_ingest_storm = '''
function ingest_ips(data, srcguid) {
    $results = $lib.set()

    for $ip in $data {
        [ inet:ipv4=$ip ]

        // Lightweight edge back to meta:source
        { [ <(seen)+ { meta:source=$srcguid } ] }

        { +inet:ipv4 $results.add($node) }
    }

    | spin |

    return($results)
}
'''

# The first line of this description will display in the Storm help
svc_cmd_get_desc = '''
Query the Example service.

Examples:

    # Query the service and create an IPv4 node
    inet:fqdn=good.com | example.get

    # Query the service and yield the created inet:ipv4 node
    inet:fqdn=good.com | example.get --yield
'''

svc_cmd_get_forms = {
    'input': [
        'inet:fqdn',
    ],
    'output': [
        'inet:ipv4',
    ],
}

svc_cmd_get_args = (
    ('--yield', {'default': False, 'action': 'store_true',
                 'help': 'Whether to yield the created nodes to the output stream.'}),
    ('--debug', {'default': False, 'action': 'store_true',
                 'help': 'Enable debug output.'}),
)

svc_cmd_get_conf = {
    'srcguid': svc_guid,
}

svc_cmd_get_storm = '''
init {
    $svc = $lib.service.get($cmdconf.svciden)
    $ingest = $lib.import(example.ingest)
    $srcguid = $cmdconf.srcguid
    $debug = $cmdopts.debug
    $yield = $cmdopts.yield
}

// $node is a special variable that references the inbound Node object
$form = $node.form()

switch $form {
    "inet:fqdn": {
        $query=$node.repr()
    }
    *: {
        $query=""
        $lib.warn("Example service does not support {form} nodes", form=$form)
    }
}

// Yield behavior to drop the inbound node
if $yield { spin }

// Call the service endpoint and ingest the results
if $query {
    if $debug { $lib.print("example.get query: {query}", query=$query) }

    $retn = $svc.getData($query)

    if $retn.status {
        $results = $ingest.ingest_ips($retn.data, $srcguid)

        if $yield {
            for $result in $results { $lib.print($result) yield $result }
        }
    } else {
        $lib.warn("example.get error: {err}", err=$retn.mesg)
    }
}
'''

svc_cmds = (
    {
        'name': f'{svc_name}.get',
        'descr': svc_cmd_get_desc,
        'cmdargs': svc_cmd_get_args,
        'cmdconf': svc_cmd_get_conf,
        'forms': svc_cmd_get_forms,
        'storm': svc_cmd_get_storm,
    },
)

svc_pkgs = (
    {
        'name': svc_name,
        'version': svc_vers,
        'synapse_minversion': svc_minvers,
        'modules': (
            {
                'name': f'{svc_name}.ingest',
                'storm': svc_mod_ingest_storm,
            },
        ),
        'commands': svc_cmds,
    },
)
