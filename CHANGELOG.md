### Release 0.2.0 (upcoming)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.1.2.0...master)
* **New feature**: missing mnemonic words

### Release 0.1.2 (2020-03-10)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.1.1.0...v0.1.2.0)
* **New feature**: missing characters in a base-16 encoded private key
* The missing base58 option can now accepte a full private key and check if it is correct while returning 
useful error message explaining why the given key was invalid.
* Simplify user input in missing base-58 (no checkbox anymore)
* Small code improvements and optimization

### Release 0.1.1 (2020-02-19)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.1.0.0...v0.1.1.0)
* (GitHub related) Added readme and continous integration using Travis
* Small SHA-256 optimization
* Add some tests
* Various small bug fixes and code improvements
* Add a special case to missing private key chars where a compressed key missing 3 chars
at unknown positions

### [Release 0.1.0 (2020-01-01)](https://github.com/Coding-Enthusiast/FinderOuter/tree/v0.1.0.0)
Initial release for new year with 2 first options:  
1. Missing Base-58 encoded private key characters
2. Message signature verification