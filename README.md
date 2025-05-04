# Hyperspace Unit (.hsu)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)<br>

Hyperspace Unit (`hyperspace-unit`) is a pure Python module that defines and interacts with a custom archive file format, `.hsu`.Its primary goal was to serve as a practical learning exercise exploring the internal workings and design principles of established archive formats like ZIP, 7z, and TAR.

While originating as an educational endeavor, the module implements a robust set of modern features, making it potentially useful for specific Python applications requiring programmatic archive handling with integrated compression, encryption, and metadata capabilities.

## Key Features

* **Context Manager Support:** Seamless integration using Python's `with` statement for safe file handling.
* **Streaming I/O:** Designed to handle large files efficiently by processing data in chunks, minimizing memory usage.
* **Multiple Compression Algorithms:** Supports various compression methods per entry:
    * `'zlib'` (Default)
    * `'bz2'`
    * `'lzma'` (Requires LZMA utils installed on some systems)
    * `'zstd'` (Requires `zstandard` library)
    * `'none'` (No compression)
* **Authenticated Encryption:** Strong per-entry encryption using AES-256-GCM, with keys derived from passwords via PBKDF2-HMAC-SHA256. Ensures both confidentiality and integrity. (Requires `cryptography` library).
* **Custom Metadata:** Attach arbitrary JSON-serializable metadata to individual entries and to the Unit itself.
* **Explicit Directory Entries:** Preserves directory structures within the Unit.
* **Integrity Checks:**
    * CRC32 checksum for each file entry's original data.
    * CRC32 checksum for the compressed central index within the Unit header.
* **Unit Integrity Testing:** Includes a `test_unit()` method to verify checksums, sizes, and decryption integrity.
* **Entry Management:** Supports adding, extracting, listing, updating (via replace), and removing entries.
* **Compaction:** Provides a `compact()` method to rebuild the Unit, removing data from deleted or updated entries to reclaim space.

## Installation

```bash
git clone https://github.com/nopde/hyperspace-unit.git
cd hyperspace-unit
pip install -r requirements.txt
```

## Usage examples

### 1. Creating an Unit and adding files
```python
import hyperspace_unit as hsu
import os

# Create dummy files
os.makedirs("temp_files/docs", exist_ok=True)
with open("temp_files/docs/report.txt", "w") as f:
    f.write("This is a secret report.")
with open("temp_files/config.ini", "w") as f:
    f.write("[Settings]\nvalue=1")

UNIT_NAME = "my_unit.hsu"
PASSWORD = "a-very-strong-password"

try:
    # Create a new unit using a 'with' statement
    with hsu.HyperspaceUnit(UNIT_NAME).open("w") as unit:
        print(f"Creating unit: {UNIT_NAME}")

        # Set archive-level metadata
        unit.set_archive_metadata({
            "project": "Project Alpha",
            "created_by": "ExampleScript"
        })
        print(" - Added archive metadata.")

        # Add a directory entry
        unit.add_directory("documents/")
        print(" - Added directory 'documents/'.")

        # Add a file with encryption and metadata
        unit.add_file(
            "temp_files/docs/report.txt",
            entry_name="documents/secret_report.txt",
            password=PASSWORD,
            compress_algo="zlib", # Default, can be omitted
            metadata={"sensitivity": "high", "version": 1.0}
        )
        print(" - Added encrypted file 'documents/secret_report.txt'.")

        # Add another file with different compression, no encryption
        unit.add_file(
            "temp_files/config.ini",
            entry_name="config.ini",
            compress_algo="bz2"
        )
        print(" - Added file 'config.ini' (bz2 compressed).")

        # Add raw data
        readme_data = b"This is the archive readme content."
        unit.add_data(
            "README.md",
            readme_data,
            compress_algo="lzma"
        )
        print(" - Added raw data as 'README.md' (lzma compressed).")

except hsu.HyperspaceUnitError as e:
    print(f"An error occurred: {e}")
finally:
    # Clean up dummy files (optional)
    # import shutil
    # if os.path.exists("temp_files"): shutil.rmtree("temp_files")
    pass
```

## Format specification

The `.hsu` file format consists of the following sections:
1. Header (Fixed Size): Contains:
   - Magic Number (`b'HSPACEU2'`)
   - Format version (1)
   - Flags (Reserved)
   - Offsets and Sizes for Metadata and Index blocks.
   - CRC32 checksum of the compressed Index block.
2. Data Blocks: Contiguous blocks containing the processed (potentially encrypted and/or compressed) data for each file entry.
3. Metadata Block: A zlib-compressed JSON object containing archive-level key-value metadata. Its presence and location are indicated in the header.
4. Index Block: A zlib-compressed JSON object located near the end of the file. It maps entry names (paths) to their metadata (type, offset, sizes, checksums, compression method, timestamp, encryption details, custom metadata).
(For a more detailed byte-level specification, please refer to the source code documentation).

## Contributing

Contributions, issues and feature requests are welcome!
