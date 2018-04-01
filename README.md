![Icon](https://github.com/netevert/delator/blob/master/docs/icon.png)
=======
[![baby-gopher](https://raw.githubusercontent.com/drnic/babygopher-site/gh-pages/images/babygopher-logo-small.png)](http://www.babygopher.org)
[![GitHub release](https://img.shields.io/github/release/netevert/delator.svg?style=flat-square)](https://github.com/netevert/delator/releases)
[![license](https://img.shields.io/github/license/netevert/delator.svg)](https://github.com/netevert/delator/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/netevert/delator)](https://goreportcard.com/report/github.com/netevert/delator)
[![Maintenance](https://img.shields.io/maintenance/yes/2018.svg?style=flat-square)]()
[![GitHub last commit](https://img.shields.io/github/last-commit/errantbot/delator.svg?style=flat-square)](https://github.com/netevert/delator/commit/master)
[![Donations](https://img.shields.io/badge/donate-bitcoin-orange.svg?logo=bitcoin&style=flat-square)](https://github.com/netevert/delator#donations)

DELATOR (*lat.* **informer**) is a tool to perform subdomain enumeration through the abusing of certificate transparency logs. It expands on the original work done by [Sheila A. Berta](https://github.com/UnaPibaGeek) with her [CTFR](https://github.com/UnaPibaGeek/ctfr) tool and leverages the speed and power of [Go](https://golang.org/). 

![demo](https://github.com/netevert/delator/blob/master/docs/demo.gif)

Using DELATOR is as simple as running: 

    ./delator -d facebook.com

**DELATOR is under active development** so do make sure you check back frequently for new releases.

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

Donations
=========

<details><summary>If you like DELATOR please consider donating</summary>
<p>
    
    Bitcoin:  13i3hFGN1RaQqdeWqmPTMuYEj9FiJWuMWf
    Litecoin: LZqLoRNHvJyuKz99mNAgVUj6M8iyEQuio9
</p>
</details>