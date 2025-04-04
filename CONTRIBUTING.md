# Contributing to this project

This project has adopted the code of conduct defined by the Contributor Covenant to clarify expected behavior in our community.
For more information see the [.NET Foundation Code of Conduct](https://dotnetfoundation.org/code-of-conduct).

## Prerequisites

This project is actively developed using the following software.
It is highly recommended that anyone contributing to this library use the same
software.

1. [Visual Studio 2022][VS]

## Building

To build this repository from the command line, you could run this command in the root of the repo:

    dotnet build

## Testing

The Visual Studio 2022 Test Explorer will list and execute all tests.

## Pull requests

Pull requests are welcome! They may contain additional test cases (e.g. to demonstrate a failure),
and/or product changes (with bug fixes or features). All product changes should be accompanied by
additional tests to cover and justify the product change unless the product change is strictly an
efficiency improvement and no outwardly observable change is expected.

In the master branch, all tests should always pass. Added tests that fail should be marked as Skip
via `[Fact(Skip = "Test does not pass yet")]` or similar message to keep our test pass rate at 100%.

 [VS]: https://www.visualstudio.com/downloads/
