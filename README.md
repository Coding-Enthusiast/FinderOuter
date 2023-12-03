[![.NET-CI](https://github.com/Coding-Enthusiast/FinderOuter/actions/workflows/dotnetCI.yml/badge.svg)](https://github.com/Coding-Enthusiast/FinderOuter/actions/workflows/dotnetCI.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Coding-Enthusiast/FinderOuter/blob/master/License)
[![Target](https://img.shields.io/badge/dynamic/xml?color=%23512bd4&label=target&query=%2F%2FTargetFramework%5B1%5D&url=https%3A%2F%2Fraw.githubusercontent.com%2FCoding-Enthusiast%2FFinderOuter%2Fmaster%2FSrc%2FFinderOuter%2FFinderOuter.csproj&logo=.net)](https://github.com/Coding-Enthusiast/FinderOuter/blob/master/Src/FinderOuter/FinderOuter.csproj)
[![Downloads](https://img.shields.io/github/downloads/Coding-Enthusiast/FinderOuter/total)](https://github.com/Coding-Enthusiast/FinderOuter/releases)

# The FinderOuter
The FinderOuter is a bitcoin recovery tool that focuses on making the recovery process easy for everyone with any level of
technical knowledge. It uses a simple user interface with a list of recovery options. Each option has an explanation and many
hints helping user figure out what is needed. It always consist of filling some text boxes and selecting some options and finally
clicking the `Find` button. This eliminates the need to read long guide pages on how to use the application. Each option also has
some example cases that can show a simple preview of how each option should be filled for different cases.  

FinderOuter is specialized for maximum efficiency, each recovery option and their parts are written from scratch and all those parts 
down to the basic cryptography used (such as SHA, ECC,...) are specialized for that operation.  

Thanks to [.Net core](https://github.com/dotnet/core) and [AvaloniaUI](https://github.com/AvaloniaUI/Avalonia) FinderOuter 
can run on all operating systems.  
This project is written fully in C# and is 100% open source and will always remain free to use. You can make a donation if you found this tool useful.  
FinderOuter is still in beta and under development. New features are slowly added and everything is optimized.  
Contribution is always welcome. Please report any bugs you find or any improvement suggestions you have by creating a new 
[issue](https://github.com/Coding-Enthusiast/FinderOuter/issues/new/choose).

## Quick guide
1. Select an option from this list depending on what you want to recover
2. Read the instructions
3. Fill in the required information
4. Select appropriate available options according to the entered data
5. There are some useful advanced options to speed up the recovery
6. Click Find button
7. Reports are printed here as the program works on recovering your keys
8. Progressbar showing the progress percentage shows up for options that use multi-threading 
(take more than a couple of seconds to complete)
9. All recovery options come with examples, click this button repeatedly to cycle through them
10. Some parts have a help button that brings up the respective FinderOuter knowledge base page

![Preview](/Doc/Images/MainPreview.jpg)

## Available recovery options
#### 1. Message signature verification  
User can enter a message signature here to verify it. In case there is a problem with the message (except being an 
actually invalid signature), the code can search to find the common issues that some signing tools have and fix them.

#### 2. Missing Base-58 characters
This option can be used to recover any base-58 encoded string with a checksum that is missing some characters. For example 
a damaged paper wallet where some characters are erased/unreadable. The position of missing characters must be known.  
It works for (1) [WIFs](https://en.bitcoin.it/wiki/Wallet_import_format) (Base-58 encoded private key) 
(2) [Addresses](https://en.bitcoin.it/wiki/Address) (Base-58 encoded P2PKH or P2SH address) 
(3) [BIP-38](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) (Base-58 encoded encrypted private key).  

There is also a "special case" for private keys missing 1, 2 or 3 characters at _unknown_ positions.

#### 3. Missing Base-16 characters
This option is similar to previous feature but works for base-16 (hexadecimal) private keys. Since there is no checksum in this
encoding it requires an additional input to check each permutation against. It accepts any address type and public keys.
This option is slower in comparison because it uses ECC and that is not yet optimized.

#### 4. Missing mini-privatekey characters
This option is similar to 2 and 3 but works for [mini-privatekeys](https://en.bitcoin.it/wiki/Mini_private_key_format)
(eg. SzavMBLoXU6kDrqtUVmffv). It requires the corresponding address or public key of the minikey to check
each possible key against, as a result it is also slower since it depends on ECC and has 2 additional hashes.

#### 5. Missing mnomonic (seed) words 
This option works for both [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) and Electrum mnemonics
that have some missing words. It requires knowing one child (private/public) key or address created from that seed and the 
exact derivation path of it.

#### 6. Missing mnemonic passphrase
This option is used to recover the extension words (aka passphrase) used in mnemonics. It works for both
[BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) and Electrum mnemonics algorithms. The available
passphrase recovery modes are:  
a. Alphanumeric: This is when the passphrase consists of letter, numbers and symbols and is random. Example: `OT!pA?8i`  
b. CustomChars: This mode allows user to define their own set of characters to be used in the passphrase.
c. _soon_

#### 7. Missing BIP-38 password
This option can recover passwords used in encrypting bitcoin private keys using the 
[BIP-38](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) proposal. The available password recovery modes 
are the same as mnemonic passphrase option.

#### 8. Missing BIP-32 derivation path
This option could be used to find derivation path of a child key (private key, public key or the address) by having the mnemonic
or the extended master keys (xprv or xpub). It only checks a hard-coded list of popular derivation paths.

#### 9. Missing characters in Armory recovery phrase
This option is used to recover Armory paper backups (containing 2 or 4 lines of 36 characters in Base-16 with custom char-set)
that are missing some of their characters. Since the last 4 characters of each line is the checksum this option can be very fast
(1 trillion keys/sec) if the checksum is available or extremely slow (100 key/sec) if not.

#### 10. Missing string encoding
This option could be used to determine the encoding of an arbitrary text. It currently supports Base-16, Base-43, Base-58, 
Base-58 with checksum and Base-64. All inputs will be converted to hexadecimal.


## Future plans
Check out roadmap here: https://github.com/Coding-Enthusiast/FinderOuter/issues/47
* Optimization is always at the top of the to-do list
* File password recovery (user knows some parts of his password but not all and has the encrypted wallet file)
* SIMD code
* GPU support

## Getting started
#### Step 1: Preparation
You can ignore this step at your own risk and skip to step 2.  
Since this project deals with _sensative information_ such as private keys, mnemonics, etc. the safest approach is to run it 
on a clean and [air-gapped](https://en.wikipedia.org/wiki/Air_gap_(networking)) computer. Easiest way of acheiving that is using
a live Linux:  
1. Download [Ubuntu](https://ubuntu.com/download/desktop) or any other Linux OS (all FinderOuter releases are tested on 64-bit
Ubuntu 20.04 before being published)
2. Verify Ubuntu's iso ([link](https://ubuntu.com/tutorials/tutorial-how-to-verify-ubuntu#1-overview))
3. Follow step 2 while you are still online
4. Disconnect network cable (to remain offline)
5. Burn that ISO on a DVD or could be a USB disk 
([link](https://ubuntu.com/tutorials/try-ubuntu-before-you-install#1-getting-started))
5. Boot into Ubuntu to run FinderOuter
6. After you are done, shut down Ubuntu and remove the medium used in step 5

#### Step 2: Download and build
If you cannot or do not want to build you can go to [releases](https://github.com/Coding-Enthusiast/FinderOuter/releases) where
the ready to run binaires are found for 3 different x64 operating systems: Windows, Linux and MacOS. 
the other two files named `Source code.zip` and `Source code.tar.gz` are the project's source code that GitHub automatically adds
at that release version's commit.  

**To build FinderOuter:**  
If you have [Visual Studio](https://visualstudio.microsoft.com/downloads/) you can clone this repository and build the included
solution file called [FinderOuter.sln](https://github.com/Coding-Enthusiast/FinderOuter/blob/master/Src/FinderOuter.sln).  
Building is also possible through these steps using command line: 
1. Get Git: https://git-scm.com/downloads
2. Get .NET 5.0 SDK: https://dotnet.microsoft.com/download (see `TargetFramework` in
[FinderOuter.csproj](https://github.com/Coding-Enthusiast/FinderOuter/blob/master/Src/FinderOuter/FinderOuter.csproj)
for the required .net version in case readme wasn't updated)
3. Clone FinderOuter `git clone https://github.com/Coding-Enthusiast/FinderOuter.git`
4. Build using `dotnet publish -c Release -r <RID> --self-contained true` (replace `<RID>` with [RID](https://docs.microsoft.com/en-us/dotnet/core/rid-catalog)
of the operating system you want to build for. e.g. `win-x64` for x64 Windows or `linux-arm64` for Linux x64 ARM)

**Important notes:**  
- Remember to build the project using `release` [configuration](https://docs.microsoft.com/en-us/dotnet/core/tools/dotnet-build)
to benefit from compiler optimizations.  
- .Net applications can be published as [self contained](https://docs.microsoft.com/en-us/dotnet/core/deploying/) which will 
increase the size of the binray by including the required framework in it. That helps running the application on any computer 
(like the live Linux explained above) without needing to install .Net separately. The size can be reduced by selecting the
`Trim unused assemblies` option.  
- This project can be built on and used on any operating system, use `-r|--runtime <RUNTIME_IDENTIFIER>` to specify OS
with the correct [RID](https://docs.microsoft.com/en-us/dotnet/core/rid-catalog).  

#### Step 3: Run
If you have compiled FinderOuter as SCD or downloaded the provided binaries there is no need to download .Net Core, otherwise it
has to be [downloaded and installed](https://dotnet.microsoft.com/download) on the system that needs to run FinderOuter.  
FinderOuter can be run by using console/terminal command `dotnet FinderOuter.dll` for Linux, `dotnet FinderOuter` on MacOs and running the 
`FinderOuter.exe` on Windows.  
Linux may require providing persmissions first
([more info](https://stackoverflow.com/questions/46843863/how-to-run-net-core-console-app-on-linux)):  
1. Provide execute permissions `chmod 777 ./FinderOuter`
2. Execute application `./FinderOuter`

## Contributing
Please first check out [conventions](https://github.com/Autarkysoft/Conventions) for information about coding styles, 
versioning, making pull requests, and more.

## Donations
If You found this tool helpful consider making a donation:  
Legacy address: 1Q9swRQuwhTtjZZ2yguFWk7m7pszknkWyk  
SegWit address: bc1q3n5t9gv40ayq68nwf0yth49dt5c799wpld376s
