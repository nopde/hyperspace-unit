# Hyperspace Unit (.hsu) Python Module

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python module for creating, reading, and managing custom container files called "Hyperspace Units" (with the `.hsu` extension). This format allows bundling multiple files and data entries into a single, potentially compressed, archive file with metadata and checksums for integrity.

## Features

* Create new `.hsu` container files.
* Add files from the filesystem or raw byte data.
* Optional `zlib` compression per entry (only applied if size is reduced).
* List entries within a unit.
* Extract specific entries or all entries.
* Retrieve metadata for each entry (original size, stored size, compression method, CRC32 checksum, timestamp).
* Lazy deletion of entries (mark as deleted without immediate removal).
* Compaction feature to permanently remove deleted entries and reclaim space.
* Basic file format validation (magic number, index integrity).

## File Format (.hsu) Overview

1.  **Header (24 bytes):**
    * Magic Number: `b'HSPACEU1'` (8 bytes)
    * Index Offset: Position of the index (8 bytes, uint64)
    * Index Size: Size of the compressed index (8 bytes, uint64)
2.  **Data Blocks:** Raw or zlib-compressed data for each entry.
3.  **Index:** zlib-compressed JSON object at the end of the file containing metadata for all active entries.

## Installation

Currently, you can use this module by cloning the repository or downloading the `hyperspace_unit.py` file and placing it in your Python project directory or a location in your `PYTHONPATH`.

```bash
git clone [https://github.com/nopde/hyperspace-unit.git](https://github.com/nopde/hyperspace-unit.git)
cd hyperspace
```

### Contributing

Contributions are welcome! If you have suggestions or find bugs, please open an issue on the GitHub repository. If you'd like to contribute code, please fork the repository and submit a pull request.