[![Build Status](https://travis-ci.com/Coding-Enthusiast/FinderOuter.svg?branch=master)](https://travis-ci.com/Coding-Enthusiast/FinderOuter)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Coding-Enthusiast/FinderOuter/blob/master/License)

# The FinderOuter
The FinderOuter is a bitcoin recovery tool that focuses on making the recovery process easy for everyone.  
There is no need to read long guide pages to learn how to use the application. Instead it will always be as easy as filling some
boxes, maybe selecting some options and clicking a button all in a user-friendly GUI.  
Each recovery option is written from scratch and all parts down to the basic cryptography used (such as SHA, ECC,...) are specialized
for maximum efficiency.

Thanks to [.Net core](https://github.com/dotnet/core) and [AvaloniaUI](https://github.com/AvaloniaUI/Avalonia) this tool 
can run on all operating systems.  
This project is written fully in C# and is 100% open source.  
FinderOuter is still in beta and under development. New features are slowly added and everything is optimized.  
Contribution is always welcome. Please report any bugs you find or any improvement suggestions you have by creating a new 
[issue](https://github.com/Coding-Enthusiast/FinderOuter/issues/new/choose).

## How to use and preview
1. Select an option from this list depending on what you want to recover
2. Read the instructions
3. Fill in the required information
4. Select appropriate available options according to the entered data
5. Some parts have tooltips for extra explanation
6. Click Find button
7. See the progress and the reports

![Preview](/Doc/Images/MainPreview.jpg)

## Available options
#### 1. Message signature verification  
User can enter a message signature here to verify it. In case there is a problem with the message (except being an 
actually invalid signature), the code can search to find the common issues that some signing tools have and fix them.

#### 2. Missing Base-58 characters
This option helps recover any base-58 encoded string with a checksum that is missing some characters. For example a damaged 
paper wallet where some characters are erased/unreadable. The position of missing characters must be known.  
It works for (1) [WIFs](https://en.bitcoin.it/wiki/Wallet_import_format) (Base-58 encoded private key) 
(2) [Addresses](https://en.bitcoin.it/wiki/Address) (Base-58 encoded P2PKH address) 
(3) [BIP-38](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) (Base-58 encoded encrypted private key).  

There is also a "special case" where a compressed private key is missing 3 characters at _unknown_ positions.

#### 3. Missing Base-16 characters
This option is similar to previous feature but works for base-16 (hexadecimal) private keys. It currently requires an address
and only checks compressed public keys. Unlike the other options, this one is very slow since it depends on ECC and that is not
yet optimized.

#### 4. Missing mini-privatekey characters
This option is similar to 2 and 3 but works for mini-privatekeys (eg. SzavMBLoXU6kDrqtUVmffv). It requires an address to check
each possible key against, as a result it is also slower since it depends on ECC and has 2 additional hashes.

#### 5. Missing mnomonic (seed) words 
This option works for [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) mnemonics (others like Electrum will
be added in the future) that have some words missing. It requires knowing one child key or address created from that seed and the 
exact path of it.

## Future plans
* Optimization is always at the top of the to-do list
* BIP-32 path finder (user has master key and at least one child key but doesn't know the derivation path)
* Password recovery (user knows some parts of his password but not all and has the encrypted wallet file)
* Converting versioned WIFs to regular WIFs (BIP-178 and early vertion 3 Electrum wallets)

## Downloading
Compiled binaries of each version can be found under [releases](https://github.com/Coding-Enthusiast/FinderOuter/releases)<sup>1</sup>.
There will only be self-contained<sup>2</sup> deployment targetting 64-bit Linux operating systems. 
There are two main reasons for this decision:  
1. SCD releases are bigger in size and targetting one OS can slightly decrease the size.
2. Since many features of this tool deal with sensitive information such as private keys, mnemonics,... that need to be 
kept secure, we strongly recommend that a Live linux is used with its network disabled.  

However if you want to run this on another platform, you still can 
[compile the source code yourself](https://github.com/Coding-Enthusiast/FinderOuter#build-from-source-code).

<sup>1</sup> There are 3 files found in "releases" page, the bigger file on top is the compiled version and the other two named
`Source code.zip` and `Source code.tar.gz` are the project's source code that GitHub automatically adds. There is no need to
download the last two files if you are looking for compiled version.  
<sup>2</sup> There is no need to download/install anything (such as .Net), everything is already included.

## Build from source code
1. Get Git: https://git-scm.com/downloads
2. Get .NET Core 3.1 SDK: https://www.microsoft.com/net/download (see `TargetFramework` 
[here](https://github.com/Coding-Enthusiast/FinderOuter/blob/master/Src/FinderOuter/FinderOuter.csproj))
3. clone FinderOuter `git clone https://github.com/Coding-Enthusiast/FinderOuter.git`
4. Build using `dotnet build`

## Running the FinderOuter
If the already compiled [SCD](https://docs.microsoft.com/en-us/dotnet/core/deploying/) release provided here is used, there
is no need to download anything else since the framework is included.  
1. Provide execute permissions `chmod 777 ./FinderOuter`
2. Execute application `./FinderOuter`
[more info](https://stackoverflow.com/questions/46843863/how-to-run-net-core-console-app-on-linux)  

If the source is compiled, then the `FinderOuter.exe` file on Windows or `FinderOuter.dll` on any other platform can be used 
(`dotnet FinderOuter.dll` in command line) to run FinderOuter.  
**Important:** Make sure [released build](https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-set-debug-and-release-configurations?view=vs-2019) is used (instead of debug) for optimization.  

**Note:** Since this project deals with _sensative information_ such as private keys and mnemonics, the safest approach is to run it 
on an air-gapped computer. Example: 
1. Download FinderOuter release or source and build it yourself (deterministic builds and PGP signature will be added in near future)
2. Download [Ubuntu](https://ubuntu.com/download/desktop)
3. Verify Ubuntu's iso ([link](https://ubuntu.com/tutorials/tutorial-how-to-verify-ubuntu#1-overview))
4. Disconnect network cable (to remain offline)
5. Boot from a DVD or USB ([link](https://ubuntu.com/tutorials/try-ubuntu-before-you-install#1-getting-started))
6. Run FinderOuter
7. Shut down Ubuntu and remove the medium used in step 5

## Contributing
Please check out [conventions](https://github.com/Autarkysoft/Conventions) for information about coding styles, 
versioning, making pull requests, and more.

## Donations
If You found this tool helpful consider making a donation:  
Legacy address: 1Q9swRQuwhTtjZZ2yguFWk7m7pszknkWyk  
SegWit address: bc1q3n5t9gv40ayq68nwf0yth49dt5c799wpld376s
