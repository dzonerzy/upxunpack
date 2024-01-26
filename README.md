## UPX Unpack

UPX unpack is a tool to unpack PE files packed with UPX, it supports latest UPX version 3.96 and PE file format 32/64bit.

## Usage

You can run the tool directly from the docker image, or build it yourself.

```
docker run --rm -it dzonerzy/upxunpack:1.0.0 bash
```

```
> docker run --rm -it dzonerzy/upxunpack:1.0.0 bash
# python upxunpack.py -h
usage: unpack.py [-h] -i INPUT [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        input file
  -o OUTPUT, --output OUTPUT
                        output directory
```

The docker image contains samples binaries in `/app/example` directory, you can test the unpacking with the following command:

```bash
> apt install -y binutils # binutils is required to have strings command
> strings example/packed-32bit.exe | grep "Hello"
>
> python upxunpack.py -i example/packed-32bit.exe
INFO:root:Unpacking example/packed-32bit.exe to packed-32bit.exe.unpacked
INFO:root:Mapping binary
[!]     api GlobalMemoryStatus (kernel32) is not implemented
[!]     api GlobalMemoryStatusEx (kernelbase) is not implemented
[!]     api RtlNtStatusToDosError (ntdll) is not implemented
[!]     api RtlSetLastWin32Error (ntdll) is not implemented
[!]     api RtlImageNtHeader (ntdll) is not implemented
[!]     api RtlImageNtHeaderEx (ntdll) is not implemented
[!]     api _initialize_onexit_table (ucrtbase) is not implemented
[!]     api _initialize_onexit_table (ucrtbase) is not implemented
INFO:root:Starting emulation
Can't read the padding content of section 'UPX1'
Data of section section '.rsrc' is too large (0xffff2000)
DEBUG:root:Dumping section b'UPX0\x00\x00\x00\x00'
DEBUG:root:Dumping section b'UPX1\x00\x00\x00\x00'
DEBUG:root:Dumping section b'.rsrc\x00\x00\x00'
DEBUG:root:Unpacked binary dumped to packed-32bit.exe.unpacked with OEP: 0x4012a5
> strings packed-32bit.exe.unpacked | grep "Hello"
Hello, World!
```

## Improvements

The final binary is not exactly the same as the original one, the sections are aligned to match their virtual address, and the IAT is not rebuilt. This is not a problem for most of the cases since the binary is unpacked and can be analyzed.
