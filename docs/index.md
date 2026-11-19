# Storm Services

stormsvcs is a collection of Storm Services, also called Advanced Power-Ups, for
[Synapse](https://synapse.docs.vertex.link/en/latest/) by The Vertex Project. Each one is a
Synapse Cell that runs in its own container next to a Cortex. It does the work that doesn't
belong inside the Cortex: calling an intelligence API, querying a database, or running an
analysis engine. A Storm package then turns the results into nodes in the graph.

The services are the Advanced Power-Up companion to
[StormLib++](https://docs.gormo.co/stormlibpp/). They're built on its Python service
toolkit, and everything they expose to Synapse is under its `slib` namespace (for example
`slib.vt.enrich` or `slib.yara.scan`).

## Using a service

Every service is deployed the same way:

1. Run its image, `ghcr.io/gormaniac/stormsvcs/<svc>`, with a persistent volume at
   `/vertex/storage`. Images are tagged `latest`, with each release's version, and with the
   commit SHA.
2. Add it to the Cortex, which installs its Storm package. Use the name from the service's
   Deployment page, for example `slib.vt`:

   ```text
   service.add <name> <telepath url of the service>
   service.list
   ```

3. Grant users the package's permissions, set any API keys or settings with its admin
   commands, and run its commands.

Each service's **Deployment** page has the exact image, configuration, secrets and
permissions. Its **Commands** page has every Storm command.

## Services

See the [service index](services.md) for every service, its Storm package and its version.

## Developing

The [developer guide](dev/index.md) covers how the monorepo is put together: the service
architecture, the service contract that CI enforces, testing, CI and image publishing,
versioning, and how to add a service or write its docs.

```{toctree}
:hidden: true

Home <self>
services
dev/index
```
