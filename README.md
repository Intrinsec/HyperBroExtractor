 # HyperBro Extractor

This program is based on the work done on project https://github.com/hvs-consulting/HyperBroExtractor


HyperBro is a custom in-memory RAT backdoor used by APT27 and associated groups (Emissary Panda, Iron Tiger, LuckyMouse...)
Once the HyperBro virus has infected a host, it's used by APT27 to execute remote commands from it's C2 server. 

## Description
This tool is able to decrypt Stage 2 (thumb.dat), decompress and extract the actual hyperBro PE file (Stage 3), and parse the configuration it embeds.


HyperBroExtractor will try to automatically bruteforce the 1 byte key and decrypt Stage 2, then it will decompress the LZNT1 compressed Stage 3 and extract the configuration.

To work with as many samples as possible, this program uses patterns scanning to find configurations.
In some cases the extraction of the configuration may fail but you can try to search for utf16 strings.

**NB:** We have recently noticed that some new samples have some of their configuration fields encrypted or obfuscated and this tool will not be able to extract all of the configuration.

## Credits

Thanks to HVS-Consulting, **Marko Dorfhuber** (https://github.com/PraMiD) and **Moritz Oettle**     (https://github.com/moettle) for the original project https://github.com/hvs-consulting/HyperBroExtractor

- CasualX (**pelite** - https://github.com/CasualX/pelite)
- Floris **Bruynooghe** (utf16string - https://github.com/flub)
- jneem (**memmem** - https://github.com/jneem/memmem)
- Matt Suiche (**rust-lzxpress** - https://github.com/comaeio/rust-lzxpress)
- **clap** (https://github.com/clap-rs/clap)
- lewisclark (**patternscan** - https://github.com/lewisclark)
## Build
    cargo build --release
## Usage
### Parameters
```
-i input file (Stage2 e.g: thumb.dat)
-o output file (extracted PE)
.\hyperbro_extractor.exe -i .\samples\thumb_dat.bin -o thumb_dat_extracted_pe.bin
```

 ## Example output
 ```
 /!\ --- HyperBro config extractor --- /!\
 [+] ==> The decryption Key is: 0xfc
 /!\ --- Successfully exported PE to : thumb_dat_extracted_pe.bin --- /!\
 [-] HyperBro Configuration registry key: config
 [-] Legit loader: vfhost.exe
 [-] First stage: VFTRACE.DLL
 [-] Second stage: thumb.dat
 [-] Windows service name: vfhost
 [-] C2 address: 80.92.206.158
 [-] C2 Path: /api/v2/ajax
 [-] Verb: POST
 [-] Named Pipe: \\.\pipe\testpipe
 [-] Mutex: 80A85553-1E05-4323-B4F9-43A4396A4507
 ```
