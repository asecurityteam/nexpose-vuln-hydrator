<a id="markdown-Nexpose-Vulnerability-Hydrator" name="Nexpose Vulnerability Hydrator"></a>
# Nexpose Vulnerability Hydrator

<https://github.com/asecurityteam/nexpose-vuln-hydrator>

<!-- TOC -->

- [Nexpose Vulnerability Hydrator](#Nexpose Vulnerability Hydrator)
    - [Overview](#overview)
    - [Quick Start](#quick-start)
    - [Configuration](#configuration)
        - [Logging](#logging)
        - [Stats](#stats)
    - [Status](#status)
    - [Contributing](#contributing)
        - [Building And Testing](#building-and-testing)
        - [Quality Gates](#quality-gates)
        - [License](#license)
        - [Contributing Agreement](#contributing-agreement)

<!-- /TOC -->

<a id="markdown-overview" name="overview"></a>
## Overview

Nexpose Vulnerability Hydrator consumes Asset events (that may be produced by [Nexpose Asset Producer](https://github.com/asecurityteam/nexpose-asset-producer)) 
and hydrates them with vulnerability details and possible solutions for those vulnerabilities, which we get from 
querying Nexpose. Once the asset is hydrated, it gets published to SQS via an SNS topic for the next service 
to consume. (See [Nexpose Vulnerability Filter](https://github.com/asecurityteam/nexpose-vuln-filter) for a service that 
consumes these hydrated events)

In order to get the vulnerabilities and solutions for the assets, we call the your Nexpose instance's API with the asset ID at
[/api/3/assets/{id}/vulnerabilities](https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssetServiceVulnerabilities)
to get the vulnerabilites for the asset, then call [/api/3/vulnerabilities/{id}](https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerability)
to get the details each specific vulnerability, [/api/3/vulnerabilities/{id}/solutions](https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerabilitySolutions) 
to get the solutions for the vulnerability, and [/api/3/solutions/{id}](https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSolution)
to get the details for each solution. 

<a id="markdown-quick-start" name="quick-start"></a>
## Quick Start

Install docker and docker-compose.

The app can be run locally by running `make run`.

This will run `docker-compose` for the serverfull project
as well as the supplied serverfull-gateway configuration.
The sample configration provided assumes there will be a stats
collector running. To disable this, remove the stats configuration
lines from the server configuration and the serverfull-gateway
configuration.

The app should now be running on port 8080.


<a id="markdown-configuration" name="configuration"></a>
## Configuration

Images of this project are built, and hosted on [DockerHub](https://cloud.docker.com/u/asecurityteam/repository/docker/asecurityteam/awsconfig-filterd). The system is configured using environment variables. The following are all of the configuration options for the system:

```bash
# (bool) Use the Lambda SDK to start the system.
VULNHYDRATOR_LAMBDAMODE="false"
# (string)
VULNHYDRATOR_PRODUCER_TYPE="BENTHOS"
# (string) The YAML or JSON text of a Benthos configuration.
VULNHYDRATOR_PRODUCER_BENTHOS_YAML=""
# (string) The URL to POST.
VULNHYDRATOR_PRODUCER_POST_ENDPOINT=""
# (string) The type of HTTP client. Choices are SMART and DEFAULT.
VULNHYDRATOR_PRODUCER_POST_HTTPCLIENT_TYPE="DEFAULT"
# (string) The full OpenAPI specification with transportd extensions.
VULNHYDRATOR_PRODUCER_POST_HTTPCLIENT_SMART_OPENAPI=""
# (string) The Nexpose host where your Nexpose instance lives (ex. https://nexpose.my-company.com)
VULNHYDRATOR_HYDRATOR_NEXPOSE_HOST: ""
# (string) The Nexpose username used to login to your nexpose instance.
VULNHYDRATOR_HYDRATOR_NEXPOSE_USERNAME: ""
# (string) The Nexpose password used to login to your nexpose instance.
VULNHYDRATOR_HYDRATOR_NEXPOSE_PASSWORD: ""
# (int) The number of records per page to retrieve.
VULNHYDRATOR_HYDRATOR_NEXPOSE_PAGESIZE: ""
```

For those who do not have access to AWS Lambda, you can run your own configuration by composing this
image with your own custom configuration of serverfull-gateway.

<a id="markdown-logging" name="logging"></a>
### Logging

This project makes use of [logevent](https://github.com/asecurityteam/logevent) which provides structured logging
using Go structs and tags. By default the project will set a logger value in the context for each request. The handler
uses the `LogFn` function defined in `pkg/domain/alias.go` to extract the logger instance from the context.

The built in logger can be configured through the serverfull runtime [configuration](https://github.com/asecurityteam/serverfull#configuration).

<a id="markdown-stats" name="stats"></a>
### Stats

This project uses [xstats](https://github.com/rs/xstats) as its underlying stats library. By default the project will
set a stat client value in the context for each request. The handler uses the `StatFn` function defined in
`pkg/domain/alias.go` to extract the logger instance from the context.

The built in stats client can be configured through the serverfull runtime [configuration](https://github.com/asecurityteam/serverfull#configuration).

Additional resources:

* [serverfull](https://github.com/asecurityteam/serverfull)
* [serverfull-gateway](https://github.com/asecurityteam/serverfull-gateway)

<a id="markdown-status" name="status"></a>
## Status

This project is in incubation which means we are not yet operating this tool in production
and the interfaces are subject to change.

<a id="markdown-contributing" name="contributing"></a>
## Contributing

If you are interested in contributing to the project, feel free to open an issue or PR.

<a id="markdown-building-and-testing" name="building-and-testing"></a>
### Building And Testing

We publish a docker image called [SDCLI](https://github.com/asecurityteam/sdcli) that
bundles all of our build dependencies. It is used by the included Makefile to help make
building and testing a bit easier. The following actions are available through the Makefile:

-   make dep

    Install the project dependencies into a vendor directory

-   make lint

    Run our static analysis suite

-   make test

    Run unit tests and generate a coverage artifact

-   make integration

    Run integration tests and generate a coverage artifact

-   make coverage

    Report the combined coverage for unit and integration tests

-   make build

    Generate a local build of the project (if applicable)

-   make run

    Run a local instance of the project (if applicable)

-   make doc

    Generate the project code documentation and make it viewable
    locally.

<a id="markdown-quality-gates" name="quality-gates"></a>
### Quality Gates

Our build process will run the following checks before going green:

-   make lint
-   make test
-   make integration
-   make coverage (combined result must be 85% or above for the project)

Running these locally, will give early indicators of pass/fail.

<a id="markdown-license" name="license"></a>
### License

This project is licensed under Apache 2.0. See LICENSE.txt for details.

<a id="markdown-contributing-agreement" name="contributing-agreement"></a>
### Contributing Agreement

Atlassian requires signing a contributor's agreement before we can accept a
patch. If you are an individual you can fill out the
[individual CLA](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=3f94fbdc-2fbe-46ac-b14c-5d152700ae5d).
If you are contributing on behalf of your company then please fill out the
[corporate CLA](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=e1c17c66-ca4d-4aab-a953-2c231af4a20b).
