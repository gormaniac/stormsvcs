# Storm Services GitHub Copilot Instructions

## Architecture Overview

The stormsvcs repo is a monorepo containing a collection of "Advanced Power-Ups" (or Storm Services) for The Vertex Project's Synapse framework. These Power-Ups are implemented as Python apps extending Synapse's Cell object. Each service comes with Storm code to expose the service's functionality to Synapse users. The services are designed to be run in a containerized environment, registered with a Synapse Cortex, and they communicate with a Storm runtime via Telepath.

### Core Components and Project Structure

As a monorepo, the stormsvcs repo contains multiple services, each with its own directory. Each service is considered self-contained and is expected to be able to run independently of the other services. The monorepo provides convenient organization, but it does not expose shared code for all services to rely on. Shared library code should be implemented in the StormLib++ project, a dependency all services must rely on. With that said, the monorepo does the following:
- A `services.toml` file for service metadata registration.
- A docker base image in `docker/` that all services must use as a starting point for their own Dockerfile.
  - Also enforces a shared Synapse and StormLib++ version across all services without comingling all the services' dependencies.
- A global `pyproject.toml` and `uv.lock` file for build/test dependencies.
- GitHub Actions workflows for building, testing, and publishing all services.
- A shared GitHub Pages documentation site for all services, built from the `doc/` directory.
- All services located under the `svcs/` directory, with each service in its own subdirectory.

Each service in the stormsvcs repo typically consists of the following core components:

- Cell Implementation:
  - A Python class that extends `synapse.lib.cell.Cell` and implements the service's external-to-Synapse functionality.
  - Exposed to Synapse via Telepath RPC, so select service methods can be called from Storm code.
  - Located in the `src/<service_name>/svc.py` file. Relies on `defs.py` and `api.py` for service metadata and Telepath API definitions.
- Storm Code:
  - A "Rapid Power-Up" (Storm Package) that exposes the service's functionality to Synapse users as a collection of Storm commands and modules.
  - The goal is to have the Python service own as much of the compute as possible and the Storm code own the entrypoint to the service and the translation of the service's data into Synapse models.
  - Located in the `src/<service_name>/pkgproto` directory.
- Docker Image:
  - A Dockerfile that builds a container image for the service, allowing an all in one deployment of the service and its dependencies.
  - Located in the `docker/` directory.
- Tests:
  - Unit tests for the service's Python and Storm code.
  - Located in the `tests/` directory.
- Extras:
  - A service specific `pyproject.toml` and `uv.lock` file for service dependencies.
  - A `README.md` file for service specific documentation. Can also be broken out into a `doc/` directory for more extensive documentation. This can be bundled into the global documentation site for all services and also packaged into the service's Storm Package and exposed to the Storm user.

## Key Patterns and Conventions

### Error Handling
- Python library code should raise exceptions and let the caller handle them. However, the service's Cell implementation should catch exceptions and return a `TelepathRetn` object with the error message to the caller. This allows the Storm code to handle errors gracefully and provide meaningful feedback to the user.
- Storm code can raise exceptions where it makes sense, especially in library code, but should handle exceptions gracefully in user-facing code. 
  - Errors should be logged via the Storm `$lib` functions, these allow for both user facing and application facing logging in one message.
  - Storm code should check for the `$lib.debug` flag and log additional information when it is set. This allows for more verbose logging in development and debugging scenarios without cluttering the logs in production.

### Coupling with StormLib++
- The `stormsvcs` repo should be thought as the "Advanced Power-Ups" extension of the StormLib++ project. All services should rely on StormLib++ for shared functionality and code reuse.
- Storm code that's better suited to be in a library should be implemented in the StormLib++ project's `slib.utils` Storm Package and imported into the service's storm package. This allows for a more modular design and encourages code reuse.
- Each service should be importing the `stormlibpp.stormpkg` and `stormlibpp.telepath` Python modules at minimum. These primitives were designed to make Storm Service development easier.
- Since this is an extension of the StormLib++ project, all Storm Services and Storm Packages should rely on the `slib` prefix for names exposed to Synapse. 

### Storm Considerations
- Packages should be configurable by users via Storm command options. This allows for more flexibility and customization of the service's functionality. 
  - Such as tag prefixes, default values, and other options that can be set by the admin.
  - These should be gated behind an admin check to ensure only authorized users can modify them.
  - Sane defaults should be provided for all options, so the service can be used out of the box without requiring configuration.
- Storm is a custom language designed for the Synapse framework. While its primary purpose is as a query language, it's a fully featured programming language with functions, variables, control flow, and a limited built-in standard library. Storm code should be written in a way that is idiomatic to the language and takes advantage of its features. 
  - The Synapse project itself provides a SKILL.md file around the Storm language and its features. This should be used as a reference for writing Storm code. See [synapse/data/skills/storm/SKILL.md](https://raw.githubusercontent.com/vertexproject/synapse/refs/heads/master/synapse/data/skills/storm/SKILL.md).
- In the context of a Storm Service, storm code is the entrypoint to the service and should be responsible for translating the service's data into Synapse models. The Python code should own as much of the compute as possible, while the Storm code should be responsible for orchestrating the service's functionality and exposing it to the user.
- Storm can be called by the user in a CLI/UI context or programmatically by various automations. Storm code should be written in a way that is application friendly (module functions should raise exceptions) and user friendly (user facing code should handle exceptions gracefully and provide meaningful feedback to the user).
  - Storm commands should avoid raising raw exceptions or quitting the storm runtime unless this is explicitly the desired behavior. As commands are often called by both users and programs.

### Telepath API Return Object
A `TelepathRetn` object is a dictionary with the following keys:
  - `status`: A boolean indicating whether the call was successful or not.
  - `mesg`: A string containing the error message if the call was not successful.
  - `data`: The return data from the call if it was successful.

This concept was introduced in Synapse example code and old "how-tos" but is now codified by the StormLib++ project. All services should use this pattern for their Telepath API return objects. 

### Code Style
- Camel casing is preferred when writing both Storm and Python code in the context of Synapse. In fact, any Storm code (or Python functions exposed directly to the Storm runtime) must be written in camel case. This is to maintain consistency with the Synapse project and its codebase.
- All Python functions/classes should be full documented with docstrings. This is to ensure that the code is maintainable and understandable by other developers. The docstrings should follow the [PEP 257](https://peps.python.org/pep-0257/) conventions. 
  - Static names should also be documented with docstrings, especially if they are exposed to the Storm runtime. 
- Lines should be kept to a maximum of 100 characters.
- Use type hints for all function signatures in Python code.

### Testing
- All code paths should have unit tests. This includes both Python and Storm code. The goal is to have a high level of test coverage to ensure the code is reliable and maintainable.
- No tests should call out to external services or APIs unless explicitly gated behind a test flag. This is to ensure that the tests are reliable and do not fail due to external factors.
- Mock data should be used for testing external service calls.
  - The Synapse framework's `synapse.tests.utils.StormPkgTest` class uses the `vcr` package to record and replay HTTP requests for testing. This allows for reliable and repeatable tests without relying on external services.
  - `vcr` should be reused for Storm Service testing as well, although it's not builtin to any test framework in Synapse. This allows for full test coverage without relying on external services. The `vcr` package is already a dependency of the Synapse framework and is available in the stormsvcs repo.
- Storm code is fully testable via the `synapse.tests.utils.StormPkgTest` class. This allows for testing Storm code in isolation without requiring a full Synapse runtime. The `StormPkgTest` class provides a way to load and execute Storm code in a controlled environment, allowing for reliable and repeatable tests.