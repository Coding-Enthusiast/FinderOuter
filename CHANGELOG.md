### Next Release (future ideas)
[Commits after previous release](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.19.1.0...master)  
[RoadMap](https://github.com/Coding-Enthusiast/FinderOuter/issues/47)

### Release 0.19.1 (2024-01-24)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.19.0.0...v0.19.1.0)  
* Fix a bug in VMs where FinderOuter crashed if user entered an invalid input
* Move to .net 8 and compile binding (UI)
* Some cleanup and UI fixes

### Release 0.19.0 (2023-11-15)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.18.0.0...v0.19.0.0)  
* Add settings to define the number of threads used in parallelism + KB entry
* Old Electrum mnemonics are still not supported but they will be rejected with a clear message
* Various bug fixes, code improvements, additional tests and some UI fixes

### Release 0.18.0 (2023-06-23)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.17.0.0...v0.18.0.0)  
* Improve the returned message (errors and reports)
* **New feature:** time estimation. Addresses [#30](https://github.com/Coding-Enthusiast/FinderOuter/issues/30)
* **New feature:** Add an AutoCompleteBox to mnemonic recovery option to suggest words based on letters the user entered
* Various bug fixes, code improvements and some additional tests

### Release 0.17.0 (2023-02-27)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.16.0.0...v0.17.0.0)  
* Removed message signature verification
* Solve issue #4 (not being able to enter words in CJK languages)
* Completely rely on new Bitcoin.Net release for ECC (has some bug fixes and slight optimization)
* Improve printed messages (errors and reports)
* Improved how Base16, Base58 and MiniKey options handle configuring search-space which solves some bugs and returns better messages
* Return a comprehensive message when an input contains invalid characters (the invalid char and index)
* Small UI improvements
* Various small bug fixes, code improvements, code cleanup and lots of new tests

### Release 0.16.0 (2022-09-19)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.15.0.0...v0.16.0.0)  
* Moving ECC to Bitcoin.Net (more tested and optimized)
* Introduce search space for BIP38 password recovery option
* Add a new option to open a file containing list of words to be used in the passphrase
* Fix checking inputs with no missing characters
* Many improvements in different recovery options
* Some additional tests, bug fixes, code and UI improvements

### Release 0.15.0 (2022-05-19)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.14.0.0...v0.15.0.0)  
* Added search space option for Base58, Base16, mini-privatekey and mnemonic recovery options
* Some code improvements and tests

### Release 0.14.0 (2022-03-07)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.13.0.0...v0.14.0.0)  
* Added the EC mult encryption mode to BIP38 password recovery option
* KnowledgeBase is slightly improved
* Old ECC code is removed
* General code improvements and cleanup
* Some small optimization
* Small UI improvements

### Release 0.13.0 (2022-02-02)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.12.1.0...v0.13.0.0)  
* **New recovery option**: recovering BIP38 passwords
* Passwords can now include space
* Password recovery options (BIP38 and BIP39) can now accept a custom set of characters
* Base58 recovery of WIFs with unknown missing char position updates progress bar now
* Small bug fix, optimization and tests

### Release 0.12.1 (2021-08-19)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.12.0.0...v0.12.1.0)  
* BugFix: set the first character of the found mnemonic passphrase correctly

### Release 0.12.0 (2021-08-13)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.11.0.0...v0.12.0.0)  
* **New recovery option**: recovering mnemonic (BIP39, Electrum) passphrase
* `Report` is improved to handle timer, progress and give a more accurate key/sec speed
* Mnemonic recovery option will return a better report when the input is not missing any words
* Small bug fix, code improvement and some tests

### Release 0.11.0 (2021-06-13)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.10.0.0...v0.11.0.0)  
* All hash algorithms are static and their arrays are allocated on the stack
* Added more hard-coded derivation paths for BIP-32 path recovery option
* Base58 algorithm for WIFs is reworked to increase the recovery speed up to 2.5x
* Two new special cases are added to WIF recovery for missing 1 and 2 characters at unknown locations
* Some code cleanup and additional tests

### Release 0.10.0 (2021-05-05)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.9.0.0...v0.10.0.0)  
**BigInteger Be Gone!**  

This release introduced a new code for Elliptic Curve Cryptography that also solves issue #9.  
Effectively this brings a ton of optimization to almost all options, mainly the mnemonic recovery and
Base16 rcovery. But also any option that required an `ICompareService` that used ECC.  
By getting rid of the old ECC code and `BigInteger` this also solves the pressure on garbage collector
and lets FinderOuter utilize the entire CPU power during parallelism.  
Speed gain in this release is usually around 200% compared to previous releases.  
Good news is that this is the initial step for more optimization! For example the current ECC implementation
uses radix 2^26 and contstant time operations, changing to radix 2^52 and using variable time operations, etc
will improve the speed more.  

Some additional changes:
* Path recovery can now accept any extended keys (xprv, ypub, zprv, ?pub, ...)
* It is now possible to recover a WIF missing up to 11 characters from the end
* Reports generated by MissingEncoding option are improved
* Various code improvements and tests
* From this version we are also releasing binaries for 3 operating systems (Linux, Windows and MacOs all x64)

### Release 0.9.0 (2021-04-05)
[Full Changelog](https://github.com/Coding-Enthusiast/FinderOuter/compare/v0.8.0.0...v0.9.0.0)
* **New recovery option**: find encoding of an arbitrary input string
* Add a new help view that shows up at startup and suggests which recovery option to choose
* Add Bknowledge Base window that contains explanation of different parts
* Some small improvements in address validation and error message

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