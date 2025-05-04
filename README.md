# X360 XEX Loader for Ghidra by Warranty Voider

this is a loader module for ghidra for XBox360 XEX files

- supports PDB/XDB files
  - In loader import page, click Advanced.
  - Tick `Load PDB File` + `Use experimental PDB loader` and untick `Process .pdata`
  - Select `MSDIA` parser
- supports XEXP delta patches

requires min. JDK 17

[![Alt text](https://img.youtube.com/vi/coGz0f7hHTM/0.jpg)](https://www.youtube.com/watch?v=coGz0f7hHTM)

<!-- this video is outdated -->
<!-- [![Alt text](https://img.youtube.com/vi/dBoofGgraKM/0.jpg)](https://www.youtube.com/watch?v=dBoofGgraKM) -->

## Build problem with gradle wrapper

EDIT:2025.04.05

it seems you have to update

```(Ghidra Install Dir)\Ghidra\application.properties```

and upgrade the gradle version like this

```application.gradle.min=8.10```

if you have problems with building from source in eclipse with the gradle wrapper.
