# web5-swift

[![SPI Swift Versions](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FTBD54566975%2Fweb5-swift%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/TBD54566975/web5-swift)
[![SPI Platforms](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FTBD54566975%2Fweb5-swift%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/TBD54566975/web5-swift)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/TBD54566975/web5-swift/badge)](https://securityscorecards.dev/viewer/?uri=github.com/TBD54566975/web5-swift)

## Prerequisites

### Cloning

After cloning this repository, run:

```
make bootstrap
```

This will configure the repository's submodules properly, and ensure you're all set to go!

## Release Guidelines

### Pre-releases

With Swift Package Manager, pre-releases are not necessary as it can directly utilize the repository's revision or branch name. For instance, to test the current version of the Web5 package, you can specify either:

```swift
  // Use the main branch
  .package(url: "https://github.com/TBD54566975/web5-swift.git", .branch("main")),

  // Use a specific commit
  .package(url: "https://github.com/TBD54566975/web5-swift.git", .revision("915f12ea53efeff3587f2d16d3aeb8c203ae7db4")),
```

### Releasing New Versions

To release a new version, initiate the `Release` workflow:

1. Select the version type: `major`, `minor`, `patch`, or `manual`.

   - For instance, if the latest version is `0.1.2`:
     - `major` will update to `1.0.0`
     - `minor` will update to `0.2.0`
     - `patch` will update to `0.1.3`
     - For `manual`, input the desired version in the Custom Version field, e.g., `0.9.0`

2. The workflow will automatically create a git tag and a GitHub release, including an automated changelog.

### Publishing Docs

API reference documentation is automatically updated and available at [https://swiftpackageindex.com/TBD54566975/web5-swift/{latest-version}/documentation/web5](https://swiftpackageindex.com/TBD54566975/web5-swift/main/documentation/web5) following each release.

### Additional Links

- [API Reference Guide](https://swiftpackageindex.com/TBD54566975/web5-swift/main/documentation/web5)
- [Developer Docs](https://developer.tbd.website/docs/)
