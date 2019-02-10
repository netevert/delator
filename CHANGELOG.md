# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2019-02-10

### Fixed

- Bug that crashed delator if the user had not created a local database
- Bug that crashed delator when A record lookups were requested on locally stored subdomains
- Minor documentation fixes and updates
- Miscellaneous fixes and improvements

## [1.2.0] - 2019-01-06

### Added

- Download and store certificate common names from transparency logs in local database
- Ability to select a specific transparency log for download
- Ability to select search source between crt.sh and local database

### Fixed

- Code formatting

## [1.1.1] - 2019-01-20

### Added

- Contribution guide and code of conduct

### Fixed

- Bug introduced by updates to crt.sh json that stopped ability to pull data from api
- Miscellaneous code fixes
- Updated readme

## [1.1.0] - 2018-12-27

### Added

- Changelog
- Check for new version available
- Concurrent A record lookups
- Tabular report

### Fixed

- Improved error handling
