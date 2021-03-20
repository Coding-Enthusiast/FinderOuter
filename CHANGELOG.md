### Next Release (future ideas)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.8.0.0...master)
* BIP-38 password recovery
* SIMD support
* A help window
* BIP-39 passphrase recovery

### Release 0.8.0 (2021-03-20)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.7.0.0...v0.8.0.0)
* Some user interface improvements
* **New recovery option**: find BIP-32 derivation path
* **New recovery option**: recover Armory backup phrases missing some characters
* Main window size has a limit so it can no longer be shrinked to nearly nothing

### Release 0.7.0 (2021-02-02)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.6.0.0...v0.7.0.0)
* General user interface improvements
* AvaloniaUI is updated to version 0.10
* Progressbar now shows the progress percentage
* A warning is added to MainWindow to inform those who build from source and forget to use `-release` (ie. if they run FinderOuter
in Debug mode by mistake)
* Menu (help and about windows) is removed
* Examples are improved, some new ones are added and the button is now showing the count and current example index
* Recovery option descriptions are slightly improved
* Fixed a bug in mnemonic recovery option when user entered a mnemonic with no missing words

### Release 0.6.0 (2020-12-24)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.5.0.0...v0.6.0.0)
* Move to .net 5.0
* Added small icons at the bottom showing the current state of the program
* **New recovery option**: ELectrum mnemonics
* Base16 recovery now has more options for secondary input (to check against)
* Add a new word list to mnemonic recovery: Portuguese

### Release 0.5.0 (2020-09-17)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.4.1.0...v0.5.0.0)  
**The Parallelization Update**  
This is the parallelism update with tons of optimization from a small 10% speed gain to more than 1800% in some cases.  
- Most of these optimizations are in Base58 recovery option.  
  - Compressed and uncompressed private key recovery uses all available CPU cores for maximum speed and at 100% capacity.
  - Two special cases were added to recover private keys that are missing characters from their end (up to 9 missing for uncompressed and 11 for compressed is the default for now and can be recovered in less than a minute).  
  - Recovery of Base58 addresses and BIP-38 encrypted keys are also optimized the same way.
- Mini private key recovery
  - It uses all available CPU cores
  - It suffers from the known issue #9
  - The extra input has more options like other recovery options to enter different types of addresses or a public key.
- Mnemonic recovery
  - New wordlist added (Czech)
  - There is a simple checkbox now to set the key index itself to be hardened
  - It suffers from the known issue #9 whenever there is EC multiplication involved (private key to public key), otherwise if there weren't any the code will run at maximum efficiency using all cores at 100% (see 5th example in mnemonic recovery)

Other most notable changes:
- Now there is a progress bar at the bottom that will be used when recovering in parallel to show the progress so far. Other times when using single core the recovery process never takes up longer than a minute (usually less than 10 seconds) so progress bar is disabled.  
- Addition of more examples for each recovery option.  
- Various code improvements and bug fixes.

### Release 0.4.1 (2020-07-23)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.4.0.0...v0.4.1.0)
* This minor release introduces the Example button in order to simplify the recovery process even more, 
it could be helpful to show how some boxes should be filled in more complex cases such as BIP-32 paths.

### Release 0.4.0 (2020-06-30)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.3.0.0...v0.4.0.0)
* **New feature**: Missing BIP-39 mnomonic words
* Decoupling comparer classes so that they can be injected as dependencies based on user selection
* Optimization of SHA512
* Various code improvements, bug fixes and additional tests

### Release 0.3.0 (2020-05-30)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.2.0.0...v0.3.0.0)
* **New feature**: Missing mini-privatekey characters
* Fix some bugs with missing base-58 cases
* Improve generated reports and the way they are created
* Various code improvements, bug fixes and additional tests

### Release 0.2.0 (2020-05-11)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.1.2.0...v0.2.0.0)
* **New feature**: Missing Base-58 can now find missing chars in addresses
* **New feature**: Missing Base-58 can now find missing chars in BIP-38 encrypted keys
* Various code improvements, bug fixes and additional tests
* Project is now using the well tested [Bitcoin.Net](https://github.com/Autarkysoft/Denovo#bitcoinnet) library as its backend

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