# web5-swift

[![SPI Swift Versions](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FTBD54566975%2Fweb5-swift%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/TBD54566975/web5-swift)
[![SPI Platforms](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FTBD54566975%2Fweb5-swift%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/TBD54566975/web5-swift)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/TBD54566975/web5-swift/badge)](https://securityscorecards.dev/viewer/?uri=github.com/TBD54566975/web5-swift)

> ⚠️ WEB5 SWIFT SDK IS CURRENTLY A WIP! ⚠️

## Prerequisites

### Cloning

After cloning this repository, run:

```
make bootstrap
```

This will configure the repository's submodules properly, and ensure you're all set to go!

## Releasing

### Pre-releases

Swift Package Manager makes pre-releases irrelevant because it can simply use the repo revision or branch name.

For example, for testing the current Web5 package code, one could use one of the below options:

```swift
  // use our main branch
  .package(url: "https://github.com/allegro/swift-junit.git", .branch("main")),

  // use a specific revision
  .package(url: "https://github.com/allegro/swift-junit.git", .revision("915f12ea53efeff3587f2d16d3aeb8c203ae7db4")),
```

### New Releases

When ready to publish new releases, the `Release` workflow can be triggered.

Steps:

1. Choose a version type: major, minor, patch or manual.

   - As an example, imagine that the current version of Web5 latest release version is 0.1.2
   - `major` will release 1.0.0
   - `minor` will release 0.2.0
   - `patch` will release 0.1.3
   - if `manual` is selected, specify the desired version in the Custom Version field, eg: `0.9.0`

2. A git tag with a GitHub will be automatically created with automated changelogs

### Publishing Docs

The API reference docs are automagically published at [https://swiftpackageindex.com/TBD54566975/web5-swift/{latest-version}/documentation/web5](https://swiftpackageindex.com/TBD54566975/web5-swift/main/documentation/web5) for every new release!
