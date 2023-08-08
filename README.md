![Icon](https://github.com/netevert/delator/blob/master/docs/icon.png)
=======
[![baby-gopher](https://raw.githubusercontent.com/drnic/babygopher-site/gh-pages/images/babygopher-logo-small.png)](http://www.babygopher.org)
[![GitHub release](https://img.shields.io/github/release/netevert/delator.svg?style=flat-square)](https://github.com/netevert/delator/releases)
[![license](https://img.shields.io/github/license/netevert/delator.svg?style=flat-square)](https://github.com/netevert/delator/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/netevert/delator?style=flat-square)](https://goreportcard.com/report/github.com/netevert/delator)

DELATOR (*lat.* **informer**) is a tool to perform subdomain enumeration and initial reconnaissance through the abusing of certificate transparency (CT) logs. It expands on the original work done by [Sheila A. Berta](https://github.com/UnaPibaGeek) with her [CTFR](https://github.com/UnaPibaGeek/ctfr) tool and leverages the speed and power of [Go](https://golang.org/).

![demo](https://github.com/netevert/delator/blob/master/docs/demo.gif)

Using DELATOR is as simple as running:

    ./delator -d facebook.com -s crt

To run DELATOR a domain (_-d_) and search source (_-s_) must always be specified.

DELATOR can also be instructed to resolve any subdomains found, giving a first indication of any live sites:

    ./delator -d facebook.com -s crt -a

DELATOR can also mine subdomains directly from CT logs for storage in a local database:

    ./delator -p

Once subdomains have been pulled from CT logs, queries can be made directly to the local database just by changing the search source from "_crt_" to "_db_":

    ./delator.exe -d starbucks.com -s db

Installation
============
There are two ways to install DELATOR on your system:

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
