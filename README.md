[![Build Status](https://travis-ci.com/Coding-Enthusiast/FinderOuter.svg?branch=master)](https://travis-ci.com/Coding-Enthusiast/FinderOuter)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Coding-Enthusiast/FinderOuter/blob/master/License)

# The FinderOuter
The FinderOuter aims to make recovery process easy for everyone by using a user friendly GUI. It will focus on simplicity so that the user doesn't have to read many pages of how-to-use in order to learn how to work with the command line. Instead user will only have to fill in a textbox or two and click a button!  
Currently the project is still new and under development. New features will slowly be added and everything will get optimized as we move forward.  

This project is written fully in c# and is stand alone with only GUI related components as its dependancies.  
Thanks to [.Net core](https://github.com/dotnet/core) and [AvaloniaUI](https://github.com/AvaloniaUI/Avalonia) this tool can run on all operating systems. 

## Available options
#### 1. Message signature verification  
User can enter a message signature (currently only for bitcoin) here to verify it. In case there is a problem with the message (except being an actually invalid signature), the code can search to find the common issues that some signing tools have.

#### 2. Missing Base-58 characters
This option helps those who have a damaged paper wallet with the base-58 encoded private key (WIF) missing a couple of characters. It currently only supports private keys but in the future more string types such as master private key (xprv...) will be added.

## Future plans
* Optimization is always at the top of the to-do list
* Mnemonic recovery (seed phrases missing a couple of words, having wrong order,...)
* BIP-32 path finder (user has master key and at least one child key but doesn't know the derivation path)
* Password recovery (user knows some parts of his password but not all and has the encrypted wallet file)

## Downloading
Compiled binaries of each version can be found under [releases](https://github.com/Coding-Enthusiast/FinderOuter/releases)<sup>1</sup>. There will only be self-contained deployment targetting 64-bit Linux operating systems. There is two main reasons for this decision:  
1. SCD releases are bigger in size and targetting one OS can slightly decrease the size.
2. Since many features of this tool deal with sensitive information such as private keys, mnemonics,... that need to be kept secure, we strongly recommend that a Live linux is used with its network disabled. 
However if you want to run this on another platform, you still can compile the source code yourself.

<sup>1</sup> There are 3 files found in "releases" page, the bigger file on top is the compiled version and the other two named
`Source code.zip` and `Source code.tar.gz` are the project's source code that GitHub automatically adds. There is no need to
download the last two files if you are looking for compiled version.

## Build from source code
1. Get Git: https://git-scm.com/downloads
2. Get .NET Core 3.0 SDK: https://www.microsoft.com/net/download (see `TargetFramework` [here](https://github.com/Coding-Enthusiast/FinderOuter/blob/master/Src/FinderOuter/FinderOuter.csproj))
3. clone FinderOuter `git clone https://github.com/Coding-Enthusiast/FinderOuter.git`
4. Build using `dotnet build`

## Running the FinderOuter
If you are using the released [SCD](https://docs.microsoft.com/en-us/dotnet/core/deploying/) release provided here you don't need to download any dependencies. The application runs on its own.  
1. Provide execute permissions `chmod 777 ./FinderOuter`
2. Execute application `./FinderOuter`
[more info](https://stackoverflow.com/questions/46843863/how-to-run-net-core-console-app-on-linux)  

If you are compiling from source, you can build and then use the `FinderOuter.exe` file on Windows or use `dotnet FinderOuter.dll` in command line on all platforms to run the application.  
Make sure you using a [released build](https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-set-debug-and-release-configurations?view=vs-2019) (not debug) for optimization.

## Contributing
Please check out [conventions](https://github.com/Autarkysoft/Conventions) for information about coding styles, versioning, making pull requests, and more.

## Donations
If You found this tool helpful consider making a donation:  
Legacy address: 1Q9swRQuwhTtjZZ2yguFWk7m7pszknkWyk  
SegWit address: bc1q3n5t9gv40ayq68nwf0yth49dt5c799wpld376s
