# -*- coding: utf-8 -*-
"""
hyperspace_unit.py

This module defines the HyperspaceUnit class, which allows for the creation,
manipulation, and extraction of files stored within a custom container format (.hsu).

The Hyperspace Unit (.hsu) file format is structured as follows:
1.  Header (Fixed Size):
    - Magic Number (8 bytes): Identifies the file as a Hyperspace Unit (b'HSPACEU1').
    - Index Offset (8 bytes, uint64): Byte offset where the index starts.
    - Index Size (8 bytes, uint64): Size of the compressed index in bytes.
2.  Data Blocks: Contiguous blocks containing the actual (potentially compressed)
    data of the archived files.
3.  Index (Variable Size, Compressed): A zlib-compressed JSON object located at
    the end of the file (position specified by Index Offset). This JSON object
    maps archived entry names to their metadata:
    {
        "entry_name": {
            "offset": int,        # Byte offset where the data block starts
            "orig_size": int,     # Original size of the file in bytes
            "stored_size": int,   # Size of the data block as stored (compressed/uncompressed)
            "crc32": int,         # CRC32 checksum of the original uncompressed data
            "compression": str,   # Compression method ("zlib" or "none")
            "timestamp": float,   # Modification timestamp (UTC epoch)
            "deleted": bool       # Flag to mark entry as deleted (for lazy deletion)
        },
        ...
    }

Usage:
    Typically used with a "with" statement to ensure proper file handling.

    # Create a new unit
    with HyperspaceUnit("my_unit.hsu").open("w") as unit:
        unit.add_file("local_file.txt", "docs/file.txt")
        unit.add_data("metadata.json", b'{"version": 1}')

    # Read an existing unit
    with HyperspaceUnit("my_unit.hsu").open("r") as unit:
        entries = unit.list_entries()
        data = unit.extract_data("docs/file.txt")

    # Add to an existing unit (opens in "append" like mode)
    with HyperspaceUnit("my_unit.hsu").open("a") as unit:
        unit.add_file("another_file.log", "logs/service.log")

Requires: Python 3.7+ (for typing hints and general features)
"""

import json
import os
import struct
import zlib
import time
import datetime
from typing import Dict, Any, Optional, List, BinaryIO, Literal

# --- Constants ---
MAGIC_NUMBER = b"HSPACEU1"  # Hyperspace Unit v1 - Keeping byte literal with single quotes as convention
HEADER_FORMAT = ">8sQQ"  # Big-endian: Magic(8s), Index Offset(Q), Index Size(Q) - Format strings often use double quotes
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
DEFAULT_COMPRESSION_LEVEL = 6  # zlib compression level (0-9)


# --- Custom Exceptions ---
class HyperspaceUnitError(Exception):
    """Base class for exceptions in this module."""

    pass


class InvalidFormatError(HyperspaceUnitError):
    """Raised when the file format is incorrect or corrupted."""

    pass


class ChecksumError(HyperspaceUnitError):
    """Raised when data integrity check (CRC32) fails."""

    pass


class EntryNotFoundError(HyperspaceUnitError, KeyError):
    """Raised when a requested entry is not found in the unit."""

    pass


# --- Main Class ---
class HyperspaceUnit:
    """
    Represents a Hyperspace Unit (.hsu) file, allowing for adding, extracting,
    listing, and managing entries within the container.
    """

    def __init__(self, filename: str):
        """
        Initializes the HyperspaceUnit object. Does not open the file yet.

        Args:
            filename (str): The path to the .hsu file.
        """
        if not filename:
            raise ValueError("Filename cannot be empty.")
        self.filename: str = filename
        self._file: Optional[BinaryIO] = None
        self._index: Dict[str, Dict[str, Any]] = {}
        self._open_mode: Optional[Literal["r", "w", "a", "r+"]] = None
        self._modified: bool = False  # Track if the index needs saving

    def open(self, mode: Literal["r", "w", "a", "r+"] = "r") -> "HyperspaceUnit":
        """
        Opens the Hyperspace Unit file in the specified mode.

        Args:
            mode (str): The mode to open the file in:
                "r": Read-only (default). Fails if the file doesn"t exist.
                "w": Write. Creates a new file or truncates an existing one.
                "a": Append. Opens for reading/writing, creating if it doesn"t exist.
                     New data is appended. Index is read if file exists.
                "r+": Read/Write. Opens an existing file for reading and writing.
                      Fails if the file doesn"t exist.

        Returns:
            HyperspaceUnit: self, allowing for chaining or use in "with" statements.

        Raises:
            ValueError: If the mode is invalid.
            FileNotFoundError: If mode is "r" or "r+" and the file doesn"t exist.
            InvalidFormatError: If the file exists but is not a valid .hsu file (in read modes).
            HyperspaceUnitError: For other file-related errors.
        """
        if self._file and not self._file.closed:
            # If already open, check if mode is compatible or reopen if necessary
            if self._open_mode == mode:
                return self  # Already open in the correct mode
            else:
                # Close and reopen is safer if mode changes significantly
                self.close()
                # Fall through to open logic

        if mode not in ("r", "w", "a", "r+"):
            raise ValueError(f'Invalid mode: "{mode}". Use "r", "w", "a", or "r+".')  # Escape inner quotes

        self._open_mode = mode
        self._index = {}
        self._modified = False
        file_exists = os.path.exists(self.filename)

        try:
            if mode == "w":
                # Create or truncate
                self._file = open(self.filename, "wb")
                self._write_header(0, 0)  # Write empty header
                # We need read access too for subsequent operations, reopen in r+b
                self._file.close()
                self._file = open(self.filename, "r+b")
                self._open_mode = "r+"  # Internally treat "w" as "r+" after creation
            elif mode == "a":
                # Append mode: open r+b, create if not exists
                self._file = open(self.filename, "r+b" if file_exists else "w+b")
                if file_exists:
                    self._read_index()  # Load existing index if file existed
                else:
                    self._write_header(0, 0)  # Write empty header for new file
                self._open_mode = "r+"  # Internally treat "a" as "r+"
            elif mode == "r":
                if not file_exists:
                    raise FileNotFoundError(f'File not found: "{self.filename}"')  # Escape inner quotes
                self._file = open(self.filename, "rb")
                self._read_index()
            elif mode == "r+":
                if not file_exists:
                    raise FileNotFoundError(f'File not found: "{self.filename}"')  # Escape inner quotes
                self._file = open(self.filename, "r+b")
                self._read_index()

        except (IOError, OSError) as e:
            self._file = None  # Ensure file is None on error
            raise HyperspaceUnitError(f'Failed to open "{self.filename}" in mode "{mode}": {e}') from e  # Escape inner quotes
        except InvalidFormatError as e:
            self.close()  # Close file if format is invalid during read
            raise e  # Re-raise the specific error

        return self

    def close(self):
        """
        Closes the Hyperspace Unit file, writing the index if necessary.
        """
        if self._file and not self._file.closed:
            # Check mode using double quotes
            if self._modified and ("w" in self._open_mode or "+" in self._open_mode):
                try:
                    self._write_index()
                except (IOError, OSError, zlib.error, json.JSONDecodeError) as e:
                    # Log or handle the error appropriately, but still try to close
                    print(f'Warning: Failed to write index on close for "{self.filename}": {e}')
                    # Depending on severity, you might want to raise an error here
            try:
                self._file.close()
            except IOError as e:
                print(f'Warning: Error closing file handle for "{self.filename}": {e}')
            finally:
                self._file = None
                self._index = {}  # Clear in-memory index
                self._open_mode = None
                self._modified = False

    def __enter__(self) -> "HyperspaceUnit":
        """Enter the runtime context related to this object."""
        # Assumes open() has been called or will be called before entering "with"
        if not self._file or self._file.closed:
            # Default to read mode if not opened explicitly before "with"
            # You might want to raise an error instead to enforce explicit open()
            # raise HyperspaceUnitError("HyperspaceUnit must be opened using .open() before \"with\"")
            if not self._open_mode:
                self.open("r")  # Default to read mode using double quotes
            else:
                # Try reopening with the last mode if file was closed
                self.open(self._open_mode)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the runtime context related to this object."""
        self.close()

    # --- Internal Header/Index Handling ---

    def _read_header(self) -> tuple[int, int]:
        """Reads and validates the header, returning index offset and size."""
        if not self._file or self._file.closed:
            raise HyperspaceUnitError("File is not open for reading header.")
        self._file.seek(0)
        header_data = self._file.read(HEADER_SIZE)
        if len(header_data) < HEADER_SIZE:
            raise InvalidFormatError("File is too small to be a valid Hyperspace Unit.")

        try:
            magic, index_offset, index_size = struct.unpack(HEADER_FORMAT, header_data)
        except struct.error as e:
            raise InvalidFormatError(f"Invalid header structure: {e}") from e

        if magic != MAGIC_NUMBER:
            raise InvalidFormatError("File is not a Hyperspace Unit (invalid magic number).")

        return index_offset, index_size

    def _write_header(self, index_offset: int, index_size: int):
        """Writes the header to the beginning of the file."""
        # Check mode using double quotes
        if not self._file or self._file.closed or "w" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError("File is not open for writing header.")
        self._file.seek(0)
        header_data = struct.pack(HEADER_FORMAT, MAGIC_NUMBER, index_offset, index_size)
        self._file.write(header_data)
        # Ensure header is written immediately, especially important for empty files
        self._file.flush()

    def _read_index(self):
        """Reads, decompresses, and parses the index from the file."""
        try:
            index_offset, index_size = self._read_header()

            if index_offset == 0 or index_size == 0:
                # Valid empty unit or index hasn't been written yet
                self._index = {}
                return

            # Check if offset and size are plausible
            self._file.seek(0, os.SEEK_END)
            file_size = self._file.tell()
            if index_offset + index_size > file_size or index_offset < HEADER_SIZE:
                raise InvalidFormatError(f"Invalid index position/size in header (Offset: {index_offset}, Size: {index_size}, File Size: {file_size}).")

            self._file.seek(index_offset)
            compressed_index = self._file.read(index_size)
            if len(compressed_index) != index_size:
                raise InvalidFormatError(f"Could not read the full index (expected {index_size} bytes, got {len(compressed_index)}).")

            index_json = zlib.decompress(compressed_index)
            self._index = json.loads(index_json.decode("utf-8"))
            # Filter out entries marked as deleted if necessary (or handle them elsewhere)
            self._index = {name: meta for name, meta in self._index.items() if not meta.get("deleted", False)}
            self._modified = False  # Index just loaded, not modified yet

        except (struct.error, zlib.error, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise InvalidFormatError(f"Failed to read or parse the index: {e}") from e
        except InvalidFormatError:  # Re-raise specific format errors from _read_header
            raise
        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f"I/O error while reading index: {e}") from e

    def _write_index(self):
        """Serializes, compresses, and writes the current index to the file."""
        # Check mode using double quotes
        if not self._file or self._file.closed or "w" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError("File is not open for writing index.")

        # Determine the position for the new index: right after the last data block.
        # This prevents overwriting data if entries were added.
        end_of_last_data_block = HEADER_SIZE
        active_entries = [meta for meta in self._index.values() if not meta.get("deleted", False)]
        if active_entries:
            end_of_last_data_block = max(
                [HEADER_SIZE]  # Ensure minimum position is after header
                + [entry["offset"] + entry["stored_size"] for entry in active_entries]
            )

        # Seek to the calculated end and truncate any old index or garbage data
        self._file.seek(end_of_last_data_block)
        self._file.truncate()  # Remove everything after the last valid data block

        index_offset = self._file.tell()  # This is where the new index will start

        if not self._index or all(meta.get("deleted", False) for meta in self._index.values()):
            # If index is empty or all entries are marked deleted, write an empty header
            self._write_header(0, 0)
            self._modified = False
            return

        # Prepare index data (only include non-deleted entries for writing)
        index_to_write = {name: meta for name, meta in self._index.items() if not meta.get("deleted", False)}
        if not index_to_write:  # Check again after filtering
            self._write_header(0, 0)
            self._modified = False
            return

        try:
            index_json = json.dumps(index_to_write, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            compressed_index = zlib.compress(index_json, level=DEFAULT_COMPRESSION_LEVEL)
            index_size = len(compressed_index)

            # Write the compressed index
            self._file.write(compressed_index)
            self._file.flush()  # Ensure index data is written

            # Update the header
            self._write_header(index_offset, index_size)
            self._file.flush()  # Ensure header update is written

            self._modified = False  # Index is now saved

        except (TypeError, zlib.error, json.JSONDecodeError) as e:
            # This indicates a programming error or data corruption
            raise HyperspaceUnitError(f"Failed to serialize or compress the index: {e}") from e
        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f"I/O error while writing index: {e}") from e

    # --- Public API Methods ---

    def add_data(self, entry_name: str, data: bytes, compress: bool = True, timestamp: Optional[float] = None):
        """
        Adds raw byte data as an entry to the Hyperspace Unit.

        Args:
            entry_name (str): The unique name/path for this entry within the unit.
                              Use forward slashes ("/") for path separators.
            data (bytes): The raw byte content to store.
            compress (bool): Whether to attempt zlib compression (default: True).
                             Compression is only used if it reduces size.
            timestamp (float, optional): The modification timestamp (UTC epoch seconds).
                                         Defaults to the current time.

        Raises:
            HyperspaceUnitError: If the file is not open in a writable mode ("w", "a", "r+").
            TypeError: If data is not bytes.
        """
        # Check mode using double quotes
        if not self._file or self._file.closed or "w" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError('Unit must be open in a writable mode ("w", "a", "r+") to add data.')  # Escape inner quotes
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        if not entry_name:
            raise ValueError("Entry name cannot be empty.")

        # Normalize entry name (e.g., remove leading slashes, use forward slashes)
        entry_name = entry_name.strip("/")

        original_size = len(data)
        crc = zlib.crc32(data)
        compression_method = "none"
        stored_data = data

        if compress:
            try:
                compressed_data = zlib.compress(data, level=DEFAULT_COMPRESSION_LEVEL)
                # Use compression only if it's smaller
                if len(compressed_data) < original_size:
                    stored_data = compressed_data
                    compression_method = "zlib"
            except zlib.error as e:
                print(f'Warning: zlib compression failed for "{entry_name}": {e}. Storing uncompressed.')

        stored_size = len(stored_data)

        # Determine write position: after the last current data block
        end_of_last_data_block = HEADER_SIZE
        active_entries = [meta for meta in self._index.values() if not meta.get("deleted", False)]
        if active_entries:
            end_of_last_data_block = max([HEADER_SIZE] + [entry["offset"] + entry["stored_size"] for entry in active_entries])

        try:
            self._file.seek(end_of_last_data_block)
            offset = self._file.tell()
            self._file.write(stored_data)
            self._file.flush()  # Ensure data is written
        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f'I/O error while writing data for "{entry_name}": {e}') from e

        # Update the index in memory
        self._index[entry_name] = {
            "offset": offset,
            "orig_size": original_size,
            "stored_size": stored_size,
            "crc32": crc,
            "compression": compression_method,
            "timestamp": timestamp if timestamp is not None else time.time(),
            "deleted": False,  # Ensure it's marked as active
        }
        self._modified = True  # Mark index as needing save

    def add_file(self, file_path: str, entry_name: Optional[str] = None, compress: bool = True):
        """
        Adds a file from the local filesystem to the Hyperspace Unit.

        Args:
            file_path (str): Path to the local file to add.
            entry_name (str, optional): Name/path to store the file under within the unit.
                                       Defaults to the basename of file_path.
                                       Use forward slashes ("/") for path separators.
            compress (bool): Whether to attempt compression (default: True).

        Raises:
            FileNotFoundError: If the local file_path does not exist.
            HyperspaceUnitError: If the unit is not open in a writable mode or other I/O errors occur.
            PermissionError: If the local file cannot be read.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f'Local file not found: "{file_path}"')
        if not os.path.isfile(file_path):
            raise ValueError(f'Path is not a file: "{file_path}"')

        if entry_name is None:
            entry_name = os.path.basename(file_path)
        entry_name = entry_name.replace(os.sep, "/").strip("/")  # Normalize to forward slashes

        try:
            timestamp = os.path.getmtime(file_path)
            with open(file_path, "rb") as f_in:
                data = f_in.read()
            self.add_data(entry_name, data, compress=compress, timestamp=timestamp)
        except (IOError, OSError) as e:
            # Catch permission errors, etc.
            raise HyperspaceUnitError(f'Failed to read local file "{file_path}": {e}') from e
        # Let add_data raise its specific errors if unit is not writable etc.

    def extract_data(self, entry_name: str) -> bytes:
        """
        Extracts the data for a given entry name as bytes.

        Args:
            entry_name (str): The name/path of the entry to extract.

        Returns:
            bytes: The original, uncompressed data of the entry.

        Raises:
            EntryNotFoundError: If the entry_name is not found or marked as deleted.
            HyperspaceUnitError: If the file is not open for reading or I/O errors occur.
            ChecksumError: If the CRC32 checksum verification fails.
            InvalidFormatError: If decompression fails or stored/original size mismatch.
        """
        # Check mode using double quotes
        if not self._file or self._file.closed or "r" not in self._open_mode and "+" not in self._open_mode:
            # Attempt to reopen in read mode if closed or not open for reading
            try:
                self.open("r")
            except Exception as e:
                raise HyperspaceUnitError(f"Unit must be open for reading to extract data. Failed to reopen: {e}") from e

        entry_name = entry_name.strip("/")
        entry_info = self._index.get(entry_name)

        if not entry_info or entry_info.get("deleted", False):
            raise EntryNotFoundError(f'Entry not found or marked as deleted: "{entry_name}"')

        offset = entry_info["offset"]
        stored_size = entry_info["stored_size"]
        original_size = entry_info["orig_size"]
        expected_crc = entry_info.get("crc32")  # Use .get for backward compatibility
        compression = entry_info["compression"]

        try:
            self._file.seek(offset)
            stored_data = self._file.read(stored_size)
        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f'I/O error reading data for "{entry_name}": {e}') from e

        if len(stored_data) != stored_size:
            raise InvalidFormatError(f'Data read error for "{entry_name}": expected {stored_size} bytes, got {len(stored_data)}.')

        try:
            if compression == "zlib":
                extracted_data = zlib.decompress(stored_data)
            elif compression == "none":
                extracted_data = stored_data
            else:
                raise InvalidFormatError(f'Unsupported compression method "{compression}" for entry "{entry_name}".')
        except zlib.error as e:
            raise InvalidFormatError(f'Decompression failed for "{entry_name}": {e}') from e

        # Verify original size
        if len(extracted_data) != original_size:
            raise InvalidFormatError(f'Size mismatch after extraction for "{entry_name}": expected {original_size}, got {len(extracted_data)}.')

        # Verify CRC32 checksum
        if expected_crc is not None:
            calculated_crc = zlib.crc32(extracted_data)
            # Ensure consistent handling of signed/unsigned CRC32 values if needed
            # crc32 can return signed ints on some Python versions/platforms
            # We stored it as whatever json dumped, let's compare consistently
            # One way is to compare unsigned:
            if (calculated_crc & 0xFFFFFFFF) != (expected_crc & 0xFFFFFFFF):
                raise ChecksumError(f'Checksum mismatch for "{entry_name}": expected {expected_crc}, calculated {calculated_crc}.')

        return extracted_data

    def extract_file(self, entry_name: str, destination_path: str):
        """
        Extracts an entry from the unit and saves it to the local filesystem.

        Args:
            entry_name (str): The name/path of the entry to extract.
            destination_path (str): The local path where the file will be saved.
                                    Parent directories will be created if they don"t exist.

        Raises:
            EntryNotFoundError: If the entry_name is not found.
            HyperspaceUnitError: If the unit is not open, I/O errors occur during extraction
                                or writing to the destination.
            ChecksumError: If data integrity check fails.
            PermissionError: If the destination path cannot be written to.
        """
        try:
            data = self.extract_data(entry_name)

            # Ensure destination directory exists
            dest_dir = os.path.dirname(destination_path)
            if dest_dir:  # Only create if dirname is not empty (i.e., not saving in current dir)
                os.makedirs(dest_dir, exist_ok=True)

            with open(destination_path, "wb") as f_out:
                f_out.write(data)

            # Try setting the modification time from metadata
            entry_info = self.get_entry_info(entry_name)
            if entry_info and "timestamp" in entry_info:
                try:
                    os.utime(destination_path, (time.time(), entry_info["timestamp"]))
                except OSError as e:
                    print(f'Warning: Could not set modification time for "{destination_path}": {e}')

        except (IOError, OSError) as e:
            # Catches file writing errors, permission errors etc.
            raise HyperspaceUnitError(f'Failed to write extracted file to "{destination_path}": {e}') from e
        # Let extract_data raise its specific errors (EntryNotFound, ChecksumError etc.)

    def extract_all(self, destination_folder: str):
        """
        Extracts all entries from the unit into the specified destination folder.
        Preserves the internal path structure.

        Args:
            destination_folder (str): The base folder where entries will be extracted.

        Raises:
            HyperspaceUnitError: If extraction of any file fails significantly.
        """
        os.makedirs(destination_folder, exist_ok=True)
        extracted_count = 0
        failed_count = 0
        print(f'Extracting all entries to "{destination_folder}"...')

        entry_list = self.list_entries()  # Get list of active entries

        for entry_name in entry_list:
            # Construct full destination path, ensuring OS compatibility
            relative_path = entry_name.replace("/", os.sep)
            target_path = os.path.join(destination_folder, relative_path)
            try:
                print(f"  Extracting: {entry_name} -> {target_path}")
                self.extract_file(entry_name, target_path)
                extracted_count += 1
            except (EntryNotFoundError, ChecksumError, HyperspaceUnitError, PermissionError) as e:
                print(f'  -> Failed to extract "{entry_name}": {e}')
                failed_count += 1
            except Exception as e:  # Catch unexpected errors
                print(f'  -> Unexpected error extracting "{entry_name}": {e}')
                failed_count += 1

        print(f"Extraction complete. {extracted_count} entries extracted, {failed_count} failed.")
        if failed_count > 0:
            # Optionally raise an error if any extraction failed
            # raise HyperspaceUnitError(f"{failed_count} entries failed to extract.")
            pass

    def list_entries(self) -> List[str]:
        """
        Returns a list of all active (non-deleted) entry names in the unit.

        Returns:
            List[str]: A sorted list of entry names.
        """
        if not self._file or self._file.closed:
            # Attempt to reopen temporarily if needed, just for listing
            try:
                with HyperspaceUnit(self.filename).open("r") as temp_unit:
                    return sorted([name for name, meta in temp_unit._index.items() if not meta.get("deleted", False)])
            except (FileNotFoundError, InvalidFormatError, HyperspaceUnitError):
                return []  # Return empty list if file doesn"t exist or is invalid
        # If already open, use the in-memory index
        return sorted([name for name, meta in self._index.items() if not meta.get("deleted", False)])

    def get_entry_info(self, entry_name: str) -> Optional[Dict[str, Any]]:
        """
        Returns the metadata dictionary for a specific active entry.

        Args:
            entry_name (str): The name of the entry.

        Returns:
            Optional[Dict[str, Any]]: The metadata dictionary, or None if the
                                      entry is not found or marked as deleted.
                                      The dictionary is a copy, modifying it
                                      won"t affect the internal index directly.
        """
        entry_name = entry_name.strip("/")
        if not self._file or self._file.closed:
            # Attempt to reopen temporarily if needed
            try:
                with HyperspaceUnit(self.filename).open("r") as temp_unit:
                    info = temp_unit._index.get(entry_name)
                    return info.copy() if info and not info.get("deleted", False) else None
            except (FileNotFoundError, InvalidFormatError, HyperspaceUnitError):
                return None

        info = self._index.get(entry_name)
        if info and not info.get("deleted", False):
            return info.copy()  # Return a copy
        return None

    def remove_entry(self, entry_name: str, permanent: bool = False):
        """
        Removes an entry from the Hyperspace Unit.

        By default (permanent=False), this performs a "lazy" delete by marking
        the entry as deleted in the index. The actual data remains in the file
        until `compact()` is called.

        If permanent=True, it attempts to rewrite the file without the
        entry"s data (calls `compact()` internally). This can be slow for
        large files.

        Args:
            entry_name (str): The name of the entry to remove.
            permanent (bool): If True, trigger a compaction to physically remove
                              the data (potentially slow). Defaults to False (lazy delete).

        Raises:
            EntryNotFoundError: If the entry_name is not found.
            HyperspaceUnitError: If the unit is not open in a writable mode ("a" or "r+").
        """
        # Check mode using double quotes
        if not self._file or self._file.closed or "w" in self._open_mode or "+" not in self._open_mode:
            # Note: "w" mode truncates, so remove doesn"t make sense there.
            # Needs "a" or "r+" to modify existing index.
            raise HyperspaceUnitError('Unit must be open in append ("a") or read/write ("r+") mode to remove entries.')

        entry_name = entry_name.strip("/")
        if entry_name not in self._index or self._index[entry_name].get("deleted", False):
            raise EntryNotFoundError(f'Entry not found or already deleted: "{entry_name}"')

        if permanent:
            print(f'Performing permanent removal of "{entry_name}" by compacting...')
            # Mark for deletion first, then compact
            self._index[entry_name]["deleted"] = True
            self._modified = True
            self.compact()  # This will rewrite the file excluding deleted entries
        else:
            # Lazy delete: just mark in the index
            self._index[entry_name]["deleted"] = True
            self._modified = True
            print(f'Entry "{entry_name}" marked for deletion. Run compact() to reclaim space.')
            # Note: The index will be updated on close() or explicit _write_index()

    def compact(self, target_filename: Optional[str] = None):
        """
        Reclaims space by rewriting the Hyperspace Unit file, excluding data
        from entries marked as deleted and potentially reordering data blocks.

        This operation can be time-consuming for large files.

        Args:
            target_filename (str, optional): Path to write the compacted unit to.
                                            If None (default), the original file
                                            is overwritten in place (using a
                                            temporary file for safety).

        Raises:
            HyperspaceUnitError: If the unit is not open, or I/O errors occur.
        """
        if not self._file or self._file.closed:
            raise HyperspaceUnitError("Unit must be open to perform compaction.")
        # Compaction requires read access, and write access to the target.
        # If overwriting inplace, need r+ mode ideally.
        # Check mode using double quotes
        if "r" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError('Unit must be open with read access ("r", "a", "r+") for compaction.')

        is_inplace = target_filename is None
        if is_inplace:
            # Need write access to overwrite original file
            # Check mode using double quotes
            if "+" not in self._open_mode:
                raise HyperspaceUnitError('Unit must be open in "a" or "r+" mode for in-place compaction.')
            temp_filename = self.filename + ".compact_tmp"
            final_filename = self.filename
        else:
            temp_filename = target_filename + ".compact_tmp"  # Temp file for the target
            final_filename = target_filename

        print(f"Starting compaction{' (in-place)' if is_inplace else f' to {final_filename}'}...")

        new_index: Dict[str, Dict[str, Any]] = {}
        current_offset = HEADER_SIZE  # Start writing data after the header

        try:
            # Open the temporary file for writing the compacted data
            with open(temp_filename, "wb") as temp_f:
                # Write a placeholder header
                temp_f.write(struct.pack(HEADER_FORMAT, MAGIC_NUMBER, 0, 0))

                # Iterate through active entries in a deterministic order (e.g., sorted by name)
                active_entry_names = sorted([name for name, meta in self._index.items() if not meta.get("deleted", False)])

                for entry_name in active_entry_names:
                    entry_info = self._index[entry_name]
                    print(f"  Copying: {entry_name}...")

                    # Read stored data from original file
                    self._file.seek(entry_info["offset"])
                    stored_data = self._file.read(entry_info["stored_size"])
                    if len(stored_data) != entry_info["stored_size"]:
                        raise HyperspaceUnitError(f'Read error during compaction for "{entry_name}".')

                    # Write data to temp file
                    temp_f.seek(current_offset)
                    temp_f.write(stored_data)

                    # Update index entry with new offset
                    new_entry_info = entry_info.copy()
                    new_entry_info["offset"] = current_offset
                    new_index[entry_name] = new_entry_info

                    current_offset += len(stored_data)  # Move offset for next block

                # --- Write the new index to the temp file ---
                index_pos = temp_f.tell()  # Should be == current_offset
                if not new_index:
                    index_size = 0
                else:
                    index_json = json.dumps(new_index, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    compressed_index = zlib.compress(index_json, level=DEFAULT_COMPRESSION_LEVEL)
                    index_size = len(compressed_index)
                    temp_f.write(compressed_index)

                # --- Write the final header to the temp file ---
                temp_f.seek(0)
                final_header = struct.pack(HEADER_FORMAT, MAGIC_NUMBER, index_pos, index_size)
                temp_f.write(final_header)

            # --- Replace original file with temp file (if inplace) ---
            if is_inplace:
                # Close the original file handle before replacing
                original_file_handle = self._file
                self._file = None  # Prevent close() from trying to write old index
                original_file_handle.close()

                # Safely replace the original file
                # On Windows, os.replace might fail if the target exists. Use shutil.move
                try:
                    import shutil

                    shutil.move(temp_filename, final_filename)
                except OSError:
                    # Fallback or more robust handling might be needed
                    os.remove(final_filename)  # Try removing first
                    os.rename(temp_filename, final_filename)

                # Reopen the original file with the current mode to continue session
                self.open(self._open_mode)  # This will read the new index

            else:
                # Just rename the temp file to the final target name
                os.replace(temp_filename, final_filename)
                # The original file remains open and unchanged in this case.
                # The index in memory still refers to the original file.

            # Update the in-memory index to reflect the compaction
            self._index = new_index
            self._modified = False  # Compaction saved the index
            print("Compaction finished successfully.")

        except Exception as e:
            # Clean up temporary file on error
            if os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except OSError:
                    pass  # Ignore cleanup error
            # If inplace and original file handle was closed, try to reopen original
            if is_inplace and (not self._file or self._file.closed):
                try:
                    self.open(self._open_mode)
                except Exception as reopen_e:
                    print(f"Warning: Could not reopen original file after failed compaction: {reopen_e}")

            raise HyperspaceUnitError(f"Compaction failed: {e}") from e


# --- Example Usage ---
if __name__ == "__main__":
    import shutil

    print("--- HyperspaceUnit Demo ---")
    UNIT_FILENAME = "demo_unit.hsu"
    EXTRACT_FOLDER = "demo_extract"

    # Clean up previous runs
    if os.path.exists(UNIT_FILENAME):
        os.remove(UNIT_FILENAME)
    if os.path.exists(EXTRACT_FOLDER):
        shutil.rmtree(EXTRACT_FOLDER)

    # 1. Create a new unit and add files/data
    print(f'\n1. Creating "{UNIT_FILENAME}" and adding entries...')
    try:
        with HyperspaceUnit(UNIT_FILENAME).open("w") as unit:
            # Add raw data
            unit.add_data("info/metadata.json", b'{"version": "1.0", "creator": "Astro"}', compress=False)
            print("  - Added info/metadata.json")

            # Create dummy files to add
            os.makedirs("temp_files", exist_ok=True)
            with open("temp_files/file1.txt", "w") as f:
                f.write("This is the first text file.\nIt has multiple lines.")
            with open("temp_files/image.jpg", "wb") as f:
                f.write(os.urandom(2048))  # Dummy binary data
            os.makedirs("temp_files/logs", exist_ok=True)
            with open("temp_files/logs/app.log", "w") as f:
                f.write(f"Log started at {datetime.datetime.now(datetime.timezone.utc)}\n")
                f.write("INFO: System initialized.\n")
                f.write("WARN: Low disk space.\n")

            # Add files
            unit.add_file("temp_files/file1.txt", "documents/text/file_one.txt", compress=True)
            print("  - Added documents/text/file_one.txt")
            unit.add_file("temp_files/image.jpg", "images/picture.jpg", compress=True)
            print("  - Added images/picture.jpg")
            unit.add_file("temp_files/logs/app.log", "system/logs/application.log", compress=True)
            print("  - Added system/logs/application.log")

        print(f'"{UNIT_FILENAME}" created successfully.')
    except Exception as e:
        print(f"Error during creation: {e}")
        # Clean up temp files even on error
        if os.path.exists("temp_files"):
            shutil.rmtree("temp_files")
        raise  # Re-raise after cleanup attempt

    # 2. List entries and get info
    print(f'\n2. Listing entries in "{UNIT_FILENAME}"...')
    try:
        with HyperspaceUnit(UNIT_FILENAME).open("r") as unit:
            entries = unit.list_entries()
            print("  Entries found:")
            for entry in entries:
                print(f"    - {entry}")

            print('\n  Getting info for "images/picture.jpg":')
            info = unit.get_entry_info("images/picture.jpg")
            if info:
                ts = datetime.datetime.fromtimestamp(info["timestamp"], datetime.timezone.utc)
                print(f"    Offset: {info['offset']}")
                print(f"    Original Size: {info['orig_size']} bytes")
                print(f"    Stored Size: {info['stored_size']} bytes")
                print(f"    Compression: {info['compression']}")
                print(f"    CRC32: {info['crc32']}")
                print(f"    Timestamp: {ts.isoformat()}")
            else:
                print("    Entry not found.")
    except Exception as e:
        print(f"Error during listing/info: {e}")

    # 3. Extract all entries
    print(f'\n3. Extracting all entries to "{EXTRACT_FOLDER}"...')
    try:
        with HyperspaceUnit(UNIT_FILENAME).open("r") as unit:
            unit.extract_all(EXTRACT_FOLDER)
    except Exception as e:
        print(f"Error during extraction: {e}")

    # 4. Append a new file
    print(f'\n4. Appending a new entry to "{UNIT_FILENAME}"...')
    try:
        with open("temp_files/new_data.bin", "wb") as f:
            f.write(b"\xde\xc0\xad\xde" * 10)  # Some binary data

        with HyperspaceUnit(UNIT_FILENAME).open("a") as unit:  # Use "a" for append
            unit.add_file("temp_files/new_data.bin", "extra/data.bin")
            print("  - Appended extra/data.bin")

        # Verify list after append
        print("\n  Listing entries after append:")
        with HyperspaceUnit(UNIT_FILENAME).open("r") as unit:
            entries = unit.list_entries()
            for entry in entries:
                print(f"    - {entry}")

    except Exception as e:
        print(f"Error during append: {e}")

    # 5. Remove an entry (lazy delete)
    print('\n5. Removing "images/picture.jpg" (lazy delete)...')
    try:
        with HyperspaceUnit(UNIT_FILENAME).open("a") as unit:  # Need "a" or "r+"
            unit.remove_entry("images/picture.jpg")

        # Verify list after removal
        print("\n  Listing entries after lazy delete:")
        with HyperspaceUnit(UNIT_FILENAME).open("r") as unit:
            entries = unit.list_entries()
            for entry in entries:
                print(f"    - {entry}")
            # Check size (should be same until compact)
            print(f"  File size after lazy delete: {os.path.getsize(UNIT_FILENAME)} bytes")

    except Exception as e:
        print(f"Error during removal: {e}")

    # 6. Compact the file (in-place)
    print(f'\n6. Compacting "{UNIT_FILENAME}" in-place...')
    try:
        size_before = os.path.getsize(UNIT_FILENAME)
        with HyperspaceUnit(UNIT_FILENAME).open("a") as unit:  # Need "a" or "r+"
            unit.compact()
        size_after = os.path.getsize(UNIT_FILENAME)
        print(f"  File size before compaction: {size_before} bytes")
        print(f"  File size after compaction:  {size_after} bytes")
        if size_after < size_before:
            print("  Compaction reduced file size.")
        else:
            print("  Compaction did not significantly reduce file size (might happen if deleted file was small or uncompressed).")

        # Verify list after compaction
        print("\n  Listing entries after compaction:")
        with HyperspaceUnit(UNIT_FILENAME).open("r") as unit:
            entries = unit.list_entries()
            for entry in entries:
                print(f"    - {entry}")

    except Exception as e:
        print(f"Error during compaction: {e}")

    # Clean up temporary files
    if os.path.exists("temp_files"):
        shutil.rmtree("temp_files")

    print("\n--- Demo Finished ---")
