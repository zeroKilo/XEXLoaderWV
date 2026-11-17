# X360 XEX Loader for Ghidra by Warranty Voider

XEXLoaderWV is a Ghidra extension for loading and analyzing Xbox 360 XEX executables.

## Features

- Supports Xbox 360 XEX executable loading and PowerPC analysis.
- Processes `.pdata` to recover function entries.
- Supports Microsoft PDB/XDB debug information:
  - Public symbols and function names.
  - Structures, unions, enums, and other reconstructed data types.
  - Function creation and verified function signatures.
  - Global-variable data types.
- Supports optional MAP symbol files.
- Supports XEXP delta patches.
- Supports optional RTTI processing.

### Importing an XEX

1. Open Ghidra and import an XEX executable.
2. Select the XEXLoaderWV loader.
3. Configure the optional loader settings:
   - **Process .pdata:** Recommended.
   - **Path to PDB/XDB file:** Select a debug information file if available.
   - **Path to MAP file:** Optional symbol map.
   - **Path to XEXP patch:** Optional executable patch.
   - **Process RTTI:** Enable if needed.
4. Start the import.

PDB/XDB and MAP files are loaded automatically when their paths are provided. No additional checkboxes or external PDB parser selection are required.

PDB reconstruction is conservative. Unsupported types are skipped, and some function or signature information may remain unavailable until further analysis.

## Building

XEXLoaderWV is a Ghidra extension written in Java.

To build the extension, use the development tools and build instructions provided with your Ghidra installation.

Compatibility with future Ghidra versions is not guaranteed and may require rebuilding or updating the extension.

## Installation

1. Download a release of XEXLoaderWV compatible with your Ghidra version.
2. Open Ghidra.
3. Navigate to **File → Install Extensions**.
4. Install the downloaded extension ZIP.
5. Restart Ghidra.

XEXLoaderWV will be available when importing supported Xbox 360 XEX executables