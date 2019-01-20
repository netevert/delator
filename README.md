![Icon](https://github.com/netevert/delator/blob/master/docs/icon.png)
=======
[![baby-gopher](https://raw.githubusercontent.com/drnic/babygopher-site/gh-pages/images/babygopher-logo-small.png)](http://www.babygopher.org)
[![GitHub release](https://img.shields.io/github/release/netevert/delator.svg?style=flat-square)](https://github.com/netevert/delator/releases)
[![license](https://img.shields.io/github/license/netevert/delator.svg?style=flat-square)](https://github.com/netevert/delator/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/netevert/delator?style=flat-square)](https://goreportcard.com/report/github.com/netevert/delator)
[![Maintenance](https://img.shields.io/maintenance/yes/2019.svg?style=flat-square)]()
[![GitHub last commit](https://img.shields.io/github/last-commit/netevert/delator.svg?style=flat-square)](https://github.com/netevert/delator/commit/master)

DELATOR (*lat.* **informer**) is a tool to perform subdomain enumeration and initial reconnaissance through the abusing of certificate transparency logs. It expands on the original work done by [Sheila A. Berta](https://github.com/UnaPibaGeek) with her [CTFR](https://github.com/UnaPibaGeek/ctfr) tool and leverages the speed and power of [Go](https://golang.org/).

![demo](https://github.com/netevert/delator/blob/master/docs/demo.gif)

Using DELATOR is as simple as running:

    ./delator -d facebook.com

DELATOR can also be instructed to resolve any subdomains found, giving a first indication of any live sites:

    ./delator -d facebook.com -a

Installation
============
There are two ways to install dnsmorph on your system:

1. Downloading the pre-compiled binaries for your platform from the [latest release page](https://github.com/netevert/delator/releases) and extracting in a directory of your choosing.

2. Downloading and compiling the source code yourself by running the following commands:

    - ```go get github.com/netevert/delator```
    - `cd /$GOPATH/src/github.com/netevert/delator`
    - `go build`

License
=======

Distributed under the terms of the [MIT](http://www.linfo.org/mitlicense.html) license, DELATOR is free and open
source software written and maintained with ❤ by NetEvert.

Versioning
==========

This project adheres to [Semantic Versioning](https://semver.org/).

Like it?
=========

 **DELATOR is under active development** so make sure you check back frequently for new releases. However if you like the tool please consider contributing.

 A particular issue with DELATOR and [CTFR](https://github.com/UnaPibaGeek/ctfr) is that both tools rely entirely on [Comodo's Certificate Search API](https://crt.sh/). If the API is discontinued the tools will cease to work. A [new version](https://github.com/netevert/delator/tree/v.1.2.0) of DELATOR is currently in the works that will allow for the download of subdomains directly from certificate transparency logs and storage in a local database. This would allow for later scanning for subdomains on demand and give DELATOR the ability to retain it's usefulness should Comodo's API disappear.
