# -*- coding: utf-8 -*-
"""
hyperspace_unit.py

This module defines the HyperspaceUnit class, which allows for the creation,
manipulation, and extraction of files stored within a custom container format (.hsu).

This version includes features like encryption, streaming, multiple compression
algorithms, custom metadata, explicit directories, and entry updates.

The Hyperspace Unit (.hsu) file format is structured as follows:
1.  Header (Fixed Size):
    - Magic Number (8 bytes): b'HSPACEU1'
    - Format Version (2 bytes, uint16): 1
    - Flags (2 bytes, uint16): Reserved for future use (e.g., indicates presence of metadata). Currently 0.
    - Reserved (4 bytes): Set to zero.
    - Metadata Offset (8 bytes, uint64): Byte offset where metadata block starts (0 if none).
    - Metadata Size (8 bytes, uint64): Size of compressed metadata block (0 if none).
    - Index Offset (8 bytes, uint64): Byte offset where the index starts.
    - Index Size (8 bytes, uint64): Size of the compressed index in bytes.
    - Index CRC32 (4 bytes, uint32): CRC32 checksum of the *compressed* index block.
2.  Data Blocks: Contiguous blocks for archived entries.
3.  Metadata Block (Optional, Variable Size, Compressed): Optional zlib-compressed
    JSON object containing archive-level metadata. Located at Metadata Offset.
4.  Index (Variable Size, Compressed): A zlib-compressed JSON object located at
    the end of the file (position specified by Index Offset). Structure remains
    the same as version 1.

Requires:
    - Python 3.7+
    - cryptography library (`pip install cryptography`)
"""

import json
import os
import struct
import zlib
import bz2
import lzma
import zstandard as zstd
import io
import time
import secrets  # For generating salt and nonce
from typing import Dict, Any, Optional, List, BinaryIO, Literal, Iterator, Callable, Tuple

# --- Cryptography Requirements ---
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("Warning: 'cryptography' library not found. Encryption features will be disabled.")
    print("Install it using: pip install cryptography")

# --- Constants ---
MAGIC_NUMBER = b"HSPACEU1"
FORMAT_VERSION = 1
# Header: Magic(8s), FormatVersion(H=u16), Flags(H=u16), Reserved(4x),
#         MetaOffset(Q), MetaSize(Q), IndexOffset(Q), IndexSize(Q), IndexCRC32(I=u32)
HEADER_FORMAT = ">8sHH4xQQQQI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

DEFAULT_COMPRESSION_ALGO = "zlib"
DEFAULT_COMPRESSION_LEVEL = {
    "zlib": 9,
    "bz2": 9,
    "lzma": 6,  # Preset level
    "zstd": 3,
}
SUPPORTED_COMPRESSION = ["none", "zlib", "bz2", "lzma", "zstd"]

# Encryption Constants (Using AES-GCM for Authenticated Encryption)
ENCRYPTION_ALGO = "aes-gcm-256"
PBKDF2_ITERATIONS = 100_000  # Adjust as needed for security/performance balance
SALT_SIZE = 16  # bytes
NONCE_SIZE = 12  # bytes (recommended for AES-GCM)
AES_KEY_SIZE = 32  # bytes (for AES-256)
TAG_SIZE = 16  # bytes (AES-GCM authentication tag)

CHUNK_SIZE = 64 * 1024  # 64KB for streaming operations

# Entry Types
ENTRY_TYPE_FILE = "file"
ENTRY_TYPE_DIRECTORY = "directory"

# Flag bits (not used yet)
FLAG_HAS_METADATA = 1 << 0


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


class EncryptionError(HyperspaceUnitError):
    """Raised for encryption/decryption specific errors."""

    pass


class DecryptionError(EncryptionError):
    """Raised specifically for failures during decryption (e.g., wrong password, tampered data)."""

    pass


class FeatureNotAvailableError(HyperspaceUnitError):
    """Raised when a feature (like encryption) is used but its dependency is missing."""

    pass


class EntryNotFoundError(HyperspaceUnitError, KeyError):
    """Raised when a requested entry is not found in the unit."""

    pass


# --- Helper Functions ---
def _derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a cryptographic key from a password using PBKDF2."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise FeatureNotAvailableError("Cryptography library is required for key derivation.")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=AES_KEY_SIZE, salt=salt, iterations=PBKDF2_ITERATIONS, backend=default_backend())
    return kdf.derive(password)


# --- Main Class ---
class HyperspaceUnit:
    """
    Represents a Hyperspace Unit (.hsu) file.
    """

    def __init__(self, filename: str):
        """Initializes the HyperspaceUnit object."""
        if not filename:
            raise ValueError("Filename cannot be empty.")
        self.filename: str = filename
        self._file: Optional[BinaryIO] = None
        self._index: Dict[str, Dict[str, Any]] = {}
        self._archive_metadata: Dict[str, Any] = {}
        self._open_mode: Optional[Literal["r", "w", "a", "r+"]] = None
        self._modified: bool = False
        self._format_version: int = 0  # Read from header
        self._flags: int = 0  # Read from header

    def open(self, mode: Literal["r", "w", "a", "r+"] = "r") -> "HyperspaceUnit":
        """Opens the Hyperspace Unit file."""
        if self._file and not self._file.closed:
            if self._open_mode == mode:
                return self
            else:
                self.close()

        if mode not in ("r", "w", "a", "r+"):
            raise ValueError(f'Invalid mode: "{mode}". Use "r", "w", "a", or "r+".')

        self._open_mode = mode
        self._index = {}
        self._archive_metadata = {}
        self._modified = False
        self._format_version = 0
        self._flags = 0
        file_exists = os.path.exists(self.filename)

        try:
            if mode == "w":
                self._file = open(self.filename, "wb")
                self._write_header(metadata_offset=0, metadata_size=0, index_offset=0, index_size=0, index_crc32=0, flags=0)  # Write empty header
                self._file.close()
                self._file = open(self.filename, "r+b")
                self._open_mode = "r+"
                self._format_version = FORMAT_VERSION
                self._flags = 0
            elif mode == "a":
                self._file = open(self.filename, "r+b" if file_exists else "w+b")
                if file_exists:
                    self._read_index()  # Reads header too
                else:
                    self._write_header(metadata_offset=0, metadata_size=0, index_offset=0, index_size=0, index_crc32=0, flags=0)
                    self._format_version = FORMAT_VERSION
                    self._flags = 0
                self._open_mode = "r+"
            elif mode == "r":
                if not file_exists:
                    raise FileNotFoundError(f'File not found: "{self.filename}"')
                self._file = open(self.filename, "rb")
                self._read_index()
            elif mode == "r+":
                if not file_exists:
                    raise FileNotFoundError(f'File not found: "{self.filename}"')
                self._file = open(self.filename, "r+b")
                self._read_index()

        except (IOError, OSError) as e:
            self._file = None
            raise HyperspaceUnitError(f'Failed to open "{self.filename}" in mode "{mode}": {e}') from e
        except InvalidFormatError as e:
            self.close()
            raise e

        return self

    def close(self):
        """Closes the Hyperspace Unit file."""
        if self._file and not self._file.closed:
            if self._modified and ("w" in self._open_mode or "+" in self._open_mode):
                try:
                    self._write_metadata_and_index()
                except Exception as e:
                    print(f'Warning: Failed to write index on close for "{self.filename}": {e}')
            try:
                self._file.close()
            except IOError as e:
                print(f'Warning: Error closing file handle for "{self.filename}": {e}')
            finally:
                self._file = None
                self._index = {}
                self._archive_metadata = {}
                self._open_mode = None
                self._modified = False
                self._format_version = 0
                self._flags = 0

    def __enter__(self) -> "HyperspaceUnit":
        """Enter the runtime context."""
        if not self._file or self._file.closed:
            if not self._open_mode:
                self.open("r")
            else:
                self.open(self._open_mode)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the runtime context."""
        self.close()

    # --- Internal Header/Index Handling ---
    def _read_header(self) -> tuple[int, int, int, int, int, int]:
        """Reads and validates the header."""
        self._file.seek(0)
        header_data = self._file.read(HEADER_SIZE)
        if len(header_data) < HEADER_SIZE:
            raise InvalidFormatError("File is too small to be a valid Hyperspace Unit.")

        try:
            magic, version, flags, meta_offset, meta_size, idx_offset, idx_size, idx_crc32 = struct.unpack(HEADER_FORMAT, header_data)
        except struct.error as e:
            raise InvalidFormatError(f"Invalid header structure: {e}") from e

        return flags, meta_offset, meta_size, idx_offset, idx_size, idx_crc32

    def _read_metadata_and_index(self):
        """Reads the metadata and index from the file."""
        if not self._file or self._file.closed:
            raise HyperspaceUnitError("File is not open for reading metadata and index.")

        self._archive_metadata = {}
        self._index = {}

        self._file.seek(0)
        initial_bytes = self._file.read(10)
        if len(initial_bytes) < 10:
            raise InvalidFormatError("File too small to determine version.")

        try:
            magic, version = struct.unpack(">8sH", initial_bytes)
        except struct.error as e:
            raise InvalidFormatError(f"Could not read magic number and version: {e}") from e

        if magic != MAGIC_NUMBER:
            raise InvalidFormatError("File is not a Hyperspace Unit (invalid magic number).")

        if version > FORMAT_VERSION:
            raise InvalidFormatError(f"Unsupported Hyperspace Unit format version: {version}. This module supports up to version {FORMAT_VERSION}.")

        flags, metadata_offset, metadata_size, index_offset, index_size, index_crc32 = self._read_header()

        self._format_version = version
        self._flags = flags

        if metadata_offset > 0 and metadata_size > 0:
            try:
                self._file.seek(metadata_offset)
                compressed_metadata = self._file.read(metadata_size)
                if len(compressed_metadata) != metadata_size:
                    raise InvalidFormatError(f"Could not read the full metadata block (expected {metadata_size} bytes, got {len(compressed_metadata)}).")
                metadata_json = zlib.decompress(compressed_metadata)
                self._archive_metadata = json.loads(metadata_json.decode("utf-8"))
            except (zlib.error, json.JSONDecodeError) as e:
                raise InvalidFormatError(f"Failed to read or parse the metadata block: {e}") from e
            except (IOError, OSError) as e:
                raise HyperspaceUnitError(f"I/O error while reading metadata block: {e}") from e

        if index_offset == 0 or index_size == 0:
            self._index = {}
            self._modified = False
            return

        try:
            self._file.seek(0, os.SEEK_END)
            file_size = self._file.tell()
            min_offset = HEADER_SIZE

            if metadata_offset > 0 and metadata_size > 0:
                min_offset = max(min_offset, metadata_offset + metadata_size)

            if index_offset < min_offset or (index_offset + index_size) > file_size:
                raise InvalidFormatError(f"Invalid index position/size (Offset: {index_offset}, Size: {index_size}, MetaEnd: {metadata_offset + metadata_size}, FileSize: {file_size}).")

            self._file.seek(index_offset)
            compressed_index = self._file.read(index_size)
            if len(compressed_index) != index_size:
                raise InvalidFormatError(f"Could not read the full index (expected {index_size} bytes, got {len(compressed_index)}).")

            if self._format_version >= 1:
                calculated_index_crc = zlib.crc32(compressed_index) & 0xFFFFFFFF
                if calculated_index_crc != index_crc32:
                    raise InvalidFormatError(f"Index CRC32 mismatch (expected {index_crc32}, got {calculated_index_crc}).")

            index_json = zlib.decompress(compressed_index)
            self._index = json.loads(index_json.decode("utf-8"))

            self._index = {name: meta for name, meta in self._index.items() if not meta.get("deleted", False)}
            self._modified = False
        except (struct.error, zlib.error, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise InvalidFormatError(f"Failed to read or parse the index: {e}") from e
        except ChecksumError:
            raise
        except InvalidFormatError:
            raise
        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f"I/O error while reading index: {e}") from e

    def _write_header(self, metadata_offset: int, metadata_size: int, index_offset: int, index_size: int, index_crc32: int, flags: int):
        """Writes the header."""
        if not self._file or self._file.closed or "w" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError("File is not open for writing header.")
        self._file.seek(0)
        header_data = struct.pack(HEADER_FORMAT, MAGIC_NUMBER, FORMAT_VERSION, flags, metadata_offset, metadata_size, index_offset, index_size, index_crc32)
        self._file.write(header_data)

    def _write_metadata_and_index(self):
        """Serializes, compresses, and writes the metadata and index."""
        if not self._file or self._file.closed or "w" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError("File is not open for writing metadata and index.")

        end_of_last_data_block = HEADER_SIZE
        active_entries = [meta for meta in self._index.values() if not meta.get("deleted", False)]
        if active_entries:
            file_entries = [e for e in active_entries if e.get("entry_type") == ENTRY_TYPE_FILE]
            if file_entries:
                end_of_last_data_block = max([HEADER_SIZE] + [entry["offset"] + entry["stored_size"] for entry in file_entries])

        try:
            self._file.seek(end_of_last_data_block)
            self._file.truncate()
        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f"Failed to truncate file before writing metadata and index: {e}") from e

        current_pos = self._file.tell()
        flags = self._flags

        metadata_offset = 0
        metadata_size = 0

        if self._archive_metadata:
            try:
                metadata_json = json.dumps(self._archive_metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                compressed_metadata = zlib.compress(metadata_json, level=DEFAULT_COMPRESSION_LEVEL["zlib"])
                metadata_offset = current_pos
                metadata_size = len(compressed_metadata)
                self._file.write(compressed_metadata)
                current_pos += metadata_size
            except (TypeError, zlib.error, json.JSONDecodeError) as e:
                raise HyperspaceUnitError(f"Failed to serialize or compress the metadata block: {e}") from e
            except (IOError, OSError) as e:
                raise HyperspaceUnitError(f"I/O error while writing metadata block: {e}") from e

        index_offset = 0
        index_size = 0
        index_crc32 = 0
        index_to_write = {name: meta for name, meta in self._index.items() if not meta.get("deleted", False)}

        if index_to_write:
            try:
                index_json = json.dumps(index_to_write, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                compressed_index = zlib.compress(index_json, level=DEFAULT_COMPRESSION_LEVEL["zlib"])
                index_offset = current_pos
                index_size = len(compressed_index)
                index_crc32 = zlib.crc32(compressed_index) & 0xFFFFFFFF
                self._file.write(compressed_index)
            except (TypeError, zlib.error, json.JSONDecodeError) as e:
                raise HyperspaceUnitError(f"Failed to serialize or compress the index: {e}") from e
            except (IOError, OSError) as e:
                raise HyperspaceUnitError(f"I/O error while writing index: {e}") from e

        try:
            self._write_header(metadata_offset, metadata_size, index_offset, index_size, index_crc32, flags)
            self._file.flush()
            self._modified = False
        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f"I/O error while writing header: {e}") from e

    def set_archive_metadata(self, data: Dict[str, Any]):
        """
        Sets the archive-level metadata. Overwrites any existing metadata.
        The metadata will be written when the file is closed or flushed.
        """
        if not self._file or self._file.closed or "w" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError("File is not open for writing metadata.")
        if not isinstance(data, dict):
            raise TypeError("Metadata must be a dictionary.")
        self._archive_metadata = data.copy()
        self._modified = True

    def get_archive_metadata(self) -> Dict[str, Any]:
        """Returns a copy of the archive-level metadata."""
        if not self._file or self._file.closed:
            try:
                with HyperspaceUnit(self.filename) as temp_unit:
                    temp_unit.open("r")
                    return temp_unit.get_archive_metadata()
            except (FileNotFoundError, InvalidFormatError, HyperspaceUnitError) as e:
                print(f"Warning: Could not reopen file to read metadata: {e}")
                return {}
        return self._archive_metadata.copy()

    def _read_index(self):
        """Reads, decompresses, and parses the index from the file."""
        try:
            _, _, _, index_offset, index_size, _ = self._read_header()

            if index_offset == 0 or index_size == 0:
                self._index = {}
                return

            self._file.seek(0, os.SEEK_END)
            file_size = self._file.tell()
            if index_offset + index_size > file_size or index_offset < HEADER_SIZE:
                raise InvalidFormatError(f"Invalid index position/size in header (Offset: {index_offset}, Size: {index_size}, File Size: {file_size}).")

            self._file.seek(index_offset)
            compressed_index = self._file.read(index_size)
            if len(compressed_index) != index_size:
                raise InvalidFormatError(f"Could not read the full index (expected {index_size} bytes, got {len(compressed_index)}).")

            # Index itself is always zlib compressed
            index_json = zlib.decompress(compressed_index)
            self._index = json.loads(index_json.decode("utf-8"))
            # Filter out deleted entries upon loading
            self._index = {name: meta for name, meta in self._index.items() if not meta.get("deleted", False)}
            self._modified = False

        except (struct.error, zlib.error, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise InvalidFormatError(f"Failed to read or parse the index: {e}") from e
        except InvalidFormatError:
            raise
        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f"I/O error while reading index: {e}") from e

    def _write_index(self):
        """Serializes, compresses, and writes the current index."""
        if not self._file or self._file.closed or "w" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError("File is not open for writing index.")

        end_of_last_data_block = HEADER_SIZE
        active_entries = [meta for meta in self._index.values() if not meta.get("deleted", False)]
        if active_entries:
            file_entries = [e for e in active_entries if e.get("entry_type") == ENTRY_TYPE_FILE]
            if file_entries:
                end_of_last_data_block = max([HEADER_SIZE] + [entry["offset"] + entry["stored_size"] for entry in file_entries])

        self._file.seek(end_of_last_data_block)
        self._file.truncate()

        index_offset = self._file.tell()

        index_to_write = {name: meta for name, meta in self._index.items() if not meta.get("deleted", False)}
        if not index_to_write:
            self._write_header(0, 0)  # Write empty header
            self._modified = False
            return

        try:
            index_json = json.dumps(index_to_write, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            # Index is always zlib compressed
            compressed_index = zlib.compress(index_json, level=DEFAULT_COMPRESSION_LEVEL["zlib"])
            index_size = len(compressed_index)

            self._file.write(compressed_index)
            self._file.flush()

            self._write_header(index_offset, index_size)  # Write header
            self._file.flush()

            self._modified = False

        except (TypeError, zlib.error, json.JSONDecodeError) as e:
            raise HyperspaceUnitError(f"Failed to serialize or compress the index: {e}") from e
        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f"I/O error while writing index: {e}") from e

    # --- Public API Methods ---

    def _add_entry_internal(
        self,
        entry_name: str,
        entry_type: str,
        data_provider: Callable[[], Iterator[bytes]],
        original_size: int,
        compress_algo: Optional[str] = DEFAULT_COMPRESSION_ALGO,
        timestamp: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
        password: Optional[str] = None,
        allow_ineffective_compression: bool = True,
    ):
        if not self._file or self._file.closed or "w" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError('Unit must be open in a writable mode ("w", "a", "r+") to add data.')
        if not entry_name:
            raise ValueError("Entry name cannot be empty.")
        if entry_type not in (ENTRY_TYPE_FILE, ENTRY_TYPE_DIRECTORY):
            raise ValueError(f"Invalid entry_type: {entry_type}")
        if compress_algo not in SUPPORTED_COMPRESSION and compress_algo is not None:
            raise ValueError(f"Unsupported compression algorithm: {compress_algo}")

        entry_name = entry_name.strip("/")
        metadata = metadata or {}
        timestamp = timestamp if timestamp is not None else time.time()

        if entry_type == ENTRY_TYPE_DIRECTORY:
            self._index[entry_name] = {"entry_type": ENTRY_TYPE_DIRECTORY, "offset": 0, "orig_size": 0, "stored_size": 0, "crc32": 0, "compression": "none", "timestamp": timestamp, "metadata": metadata, "deleted": False}
            self._modified = True
            return

        crc_calculator = zlib.crc32(b"")
        stored_size_calculated = 0
        encryption_info = None
        derived_key = None
        encryptor = None
        salt = None
        nonce = None
        compressor = None
        actual_compress_algo = compress_algo if compress_algo is not None else "none"
        processed_data_buffer = io.BytesIO()

        if actual_compress_algo == "zlib":
            compressor = zlib.compressobj(level=DEFAULT_COMPRESSION_LEVEL[actual_compress_algo])
        elif actual_compress_algo == "bz2":
            compressor = bz2.BZ2Compressor(DEFAULT_COMPRESSION_LEVEL[actual_compress_algo])
        elif actual_compress_algo == "lzma":
            compressor = lzma.LZMACompressor(format=lzma.FORMAT_XZ, preset=DEFAULT_COMPRESSION_LEVEL[actual_compress_algo])
        elif actual_compress_algo == "zstd":
            try:
                zstd_cctx = zstd.ZstdCompressor(level=DEFAULT_COMPRESSION_LEVEL[actual_compress_algo])
                compressor = zstd_cctx.compressobj()
            except Exception as e:
                raise HyperspaceUnitError(f"Failed to create Zstandard compressor: {e}") from e

        if password:
            if not CRYPTOGRAPHY_AVAILABLE:
                raise FeatureNotAvailableError("Cryptography library required for encryption.")
            salt = secrets.token_bytes(SALT_SIZE)
            nonce = secrets.token_bytes(NONCE_SIZE)
            derived_key = _derive_key(password.encode("utf-8"), salt)
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            encryption_info = {
                "algo": ENCRYPTION_ALGO,
                "salt": salt.hex(),
                "nonce": nonce.hex(),
            }

        end_of_last_data_block = HEADER_SIZE
        active_entries = [meta for meta in self._index.values() if not meta.get("deleted", False)]
        file_entries = [e for e in active_entries if e.get("entry_type") == ENTRY_TYPE_FILE]
        if file_entries:
            end_of_last_data_block = max([HEADER_SIZE] + [entry["offset"] + entry["stored_size"] for entry in file_entries])

        offset = 0

        try:
            data_iterator = data_provider()

            for chunk in data_iterator:
                if not isinstance(chunk, bytes):
                    raise TypeError("Data iterator must yield bytes.")

                crc_calculator = zlib.crc32(chunk, crc_calculator)

                if compressor:
                    try:
                        compressed_chunk = compressor.compress(chunk)
                    except Exception as e_compress:
                        raise HyperspaceUnitError(f"Failed to compress data: {e_compress}") from e_compress
                else:
                    compressed_chunk = chunk

                if encryptor:
                    encrypted_chunk = encryptor.update(compressed_chunk)
                else:
                    encrypted_chunk = compressed_chunk

                if encrypted_chunk:
                    processed_data_buffer.write(encrypted_chunk)

            if compressor:
                try:
                    final_compressed_chunk = compressor.flush()
                except Exception as e_compress:
                    raise HyperspaceUnitError(f"Failed to flush compressor: {e_compress}") from e_compress

                if final_compressed_chunk:
                    if encryptor:
                        encrypted_chunk = encryptor.update(final_compressed_chunk)
                    else:
                        encrypted_chunk = final_compressed_chunk
                    if encrypted_chunk:
                        processed_data_buffer.write(encrypted_chunk)

            if encryptor:
                final_encrypted_chunk = encryptor.finalize()
                processed_data_buffer.write(final_encrypted_chunk)
                if encryption_info:
                    encryption_info["tag"] = encryptor.tag.hex()

            stored_size_calculated = processed_data_buffer.tell()
            final_compress_algo = actual_compress_algo

            if actual_compress_algo != "none" and stored_size_calculated >= original_size:
                if not allow_ineffective_compression:
                    raise HyperspaceUnitError(f"Compression '{actual_compress_algo}' resulted in larger or equal size ({stored_size_calculated} >= {original_size}) and ineffective compression is disallowed.")
                else:
                    print(f"      Warning: Compression '{actual_compress_algo}' for '{entry_name}' resulted in larger/equal size ({stored_size_calculated} >= {original_size}). Storing compressed data.")
                    pass

            self._file.seek(end_of_last_data_block)
            offset = self._file.tell()
            processed_data_buffer.seek(0)
            buffer_chunk_size = CHUNK_SIZE
            while True:
                chunk_to_write = processed_data_buffer.read(buffer_chunk_size)
                if not chunk_to_write:
                    break
                self._file.write(chunk_to_write)

            self._file.flush()

        except StopIteration:
            try:
                if compressor:
                    final_compressed_chunk = compressor.flush()
                    if final_compressed_chunk:
                        if encryptor:
                            encrypted_chunk = encryptor.update(final_compressed_chunk)
                        else:
                            encrypted_chunk = final_compressed_chunk
                        if encrypted_chunk:
                            processed_data_buffer.write(encrypted_chunk)
                if encryptor:
                    final_encrypted_chunk = encryptor.finalize()
                    processed_data_buffer.write(final_encrypted_chunk)
                    if encryption_info:
                        encryption_info["tag"] = encryptor.tag.hex()

                stored_size_calculated = processed_data_buffer.tell()
                final_compress_algo = actual_compress_algo

                self._file.seek(end_of_last_data_block)
                offset = self._file.tell()
                processed_data_buffer.seek(0)
                buffer_chunk_size = CHUNK_SIZE
                while True:
                    chunk_to_write = processed_data_buffer.read(buffer_chunk_size)
                    if not chunk_to_write:
                        break
                    self._file.write(chunk_to_write)
                self._file.flush()

                if original_size != 0:
                    print(f"Warning: Data provider for '{entry_name}' was empty, but original_size was {original_size}.")

            except Exception as e_stop:
                raise HyperspaceUnitError(f'Error during finalization after empty data stream for "{entry_name}": {e_stop}') from e_stop

        except (IOError, OSError, TypeError, ValueError) as e:
            raise HyperspaceUnitError(f'Error processing or writing data for "{entry_name}": {e}') from e
        finally:
            processed_data_buffer.close()

        self._index[entry_name] = {
            "entry_type": ENTRY_TYPE_FILE,
            "offset": offset,
            "orig_size": original_size,
            "stored_size": stored_size_calculated,
            "crc32": crc_calculator & 0xFFFFFFFF,
            "compression": final_compress_algo,
            "timestamp": timestamp,
            "metadata": metadata,
            "deleted": False,
        }
        if encryption_info:
            self._index[entry_name]["encryption"] = encryption_info

        self._modified = True

    def add_data(self, entry_name: str, data: bytes, compress_algo: Optional[str] = DEFAULT_COMPRESSION_ALGO, timestamp: Optional[float] = None, metadata: Optional[Dict[str, Any]] = None, password: Optional[str] = None, allow_ineffective_compression: bool = True):
        """Adds raw byte data as a file entry."""
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")

        def provider():
            yield data

        self._add_entry_internal(entry_name, ENTRY_TYPE_FILE, provider, len(data), compress_algo, timestamp, metadata, password, allow_ineffective_compression)

    def add_file(self, file_path: str, entry_name: Optional[str] = None, compress_algo: Optional[str] = DEFAULT_COMPRESSION_ALGO, metadata: Optional[Dict[str, Any]] = None, password: Optional[str] = None, allow_ineffective_compression: bool = True):
        """Adds a file from the local filesystem."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f'Local file not found: "{file_path}"')
        if not os.path.isfile(file_path):
            raise ValueError(f'Path is not a file: "{file_path}"')

        if entry_name is None:
            entry_name = os.path.basename(file_path)
        entry_name = entry_name.replace(os.sep, "/").strip("/")

        try:
            timestamp = os.path.getmtime(file_path)
            original_size = os.path.getsize(file_path)

            def provider():
                try:
                    with open(file_path, "rb") as f_in:
                        while True:
                            chunk = f_in.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            yield chunk
                except (IOError, OSError) as e_prov:
                    raise HyperspaceUnitError(f'Failed to read local file "{file_path}": {e_prov}') from e_prov

            self._add_entry_internal(entry_name, ENTRY_TYPE_FILE, provider, original_size, compress_algo, timestamp, metadata, password, allow_ineffective_compression)
        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f'Failed to read local file "{file_path}": {e}') from e

    def add_stream(self, entry_name: str, stream: BinaryIO, original_size: int, compress_algo: Optional[str] = DEFAULT_COMPRESSION_ALGO, timestamp: Optional[float] = None, metadata: Optional[Dict[str, Any]] = None, password: Optional[str] = None, allow_inefective_compression: bool = True):
        """Adds data from a readable binary stream."""
        if not hasattr(stream, "read"):
            raise TypeError("Stream object must have a 'read' method.")

        def provider():
            while True:
                chunk = stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk

        self._add_entry_internal(entry_name, ENTRY_TYPE_FILE, provider, original_size, compress_algo, timestamp, metadata, password, allow_inefective_compression)

    def add_directory(self, entry_name: str, timestamp: Optional[float] = None, metadata: Optional[Dict[str, Any]] = None):
        """Adds an explicit directory entry."""
        timestamp = timestamp if timestamp is not None else time.time()

        def empty_provider():
            yield b""

        self._add_entry_internal(entry_name, ENTRY_TYPE_DIRECTORY, empty_provider, 0, "none", timestamp, metadata, None, None)

    def _extract_entry_internal(
        self,
        entry_name: str,
        target_iterator_func,  # Function that accepts a chunk and processes it
        password: Optional[str] = None,
    ):
        """Internal helper for extracting data (to bytes or stream)."""
        if not self._file or self._file.closed or "r" not in self._open_mode and "+" not in self._open_mode:
            try:
                self.open("r")
            except Exception as e:
                raise HyperspaceUnitError(f"Unit must be open for reading. Failed to reopen: {e}") from e

        entry_name = entry_name.strip("/")
        entry_info = self._index.get(entry_name)

        if not entry_info or entry_info.get("deleted", False):
            raise EntryNotFoundError(f'Entry not found or marked as deleted: "{entry_name}"')

        if entry_info.get("entry_type") == ENTRY_TYPE_DIRECTORY:
            raise IsADirectoryError(f'Cannot extract data from a directory entry: "{entry_name}"')
        if entry_info.get("entry_type") != ENTRY_TYPE_FILE:
            raise HyperspaceUnitError(f"Cannot extract data from entry type: {entry_info.get('entry_type')}")

        offset = entry_info["offset"]
        stored_size = entry_info["stored_size"]
        original_size = entry_info["orig_size"]
        expected_crc = entry_info.get("crc32")
        compression = entry_info["compression"]
        encryption_meta = entry_info.get("encryption")

        # --- Decryption Setup ---
        derived_key = None
        decryptor = None
        if encryption_meta:
            if not password:
                raise DecryptionError(f'Password required to decrypt entry "{entry_name}".')
            if not CRYPTOGRAPHY_AVAILABLE:
                raise FeatureNotAvailableError("Cryptography library required for decryption.")
            try:
                salt = bytes.fromhex(encryption_meta["salt"])
                nonce = bytes.fromhex(encryption_meta["nonce"])
                tag = bytes.fromhex(encryption_meta["tag"])  # Tag is needed for GCM mode
                derived_key = _derive_key(password.encode("utf-8"), salt)
                # Initialize Cipher with GCM mode including the tag for verification on finalize
                cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce, tag), backend=default_backend())
                decryptor = cipher.decryptor()
            except (ValueError, KeyError) as e:
                raise InvalidFormatError(f'Invalid encryption metadata for "{entry_name}": {e}') from e

        # --- Decompression Setup ---
        decompressor = None
        if compression == "zlib":
            decompressor = zlib.decompressobj()
        elif compression == "bz2":
            decompressor = bz2.BZ2Decompressor()
        elif compression == "lzma":
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        elif compression == "zstd":
            try:
                zstd_dctx = zstd.ZstdDecompressor()
                decompressor = zstd_dctx.decompressobj()
            except Exception as e:
                raise HyperspaceUnitError(f"Failed to create Zstandard decompressor: {e}") from e
        elif compression != "none":
            raise InvalidFormatError(f"Unsupported compression method '{compression}' for entry '{entry_name}'.")

        # --- Read, Decrypt, Decompress, CRC Check ---
        crc_calculator = zlib.crc32(b"")
        total_extracted_size = 0
        processed_stored_bytes = 0

        try:
            self._file.seek(offset)
            # Process in chunks
            while processed_stored_bytes < stored_size:
                # Determine how much to read, considering potential final decryptor chunk
                read_size = min(CHUNK_SIZE, stored_size - processed_stored_bytes)
                stored_chunk = self._file.read(read_size)
                if not stored_chunk:
                    # This should ideally not happen if stored_size is correct
                    raise InvalidFormatError(f'Premature end of file while reading data for "{entry_name}". Expected {stored_size} bytes, read {processed_stored_bytes}.')
                processed_stored_bytes += len(stored_chunk)

                # 1. Decrypt (if needed)
                if decryptor:
                    # Decrypt chunk by chunk
                    decrypted_chunk = decryptor.update(stored_chunk)
                else:
                    decrypted_chunk = stored_chunk  # Pass through if not encrypted

                # 2. Decompress (if needed)
                if decompressor:
                    # Feed decrypted (but compressed) data to decompressor
                    try:
                        decompressed_data = decompressor.decompress(decrypted_chunk)
                    # Corrected: Catch specific zlib/lzma errors and generic EOF/ValueError for bz2
                    except zlib.error as decomp_err:
                        raise InvalidFormatError(f'Decompression failed (zlib) for "{entry_name}": {decomp_err}') from decomp_err
                    except lzma.LZMAError as decomp_err:
                        raise InvalidFormatError(f'Decompression failed (lzma) for "{entry_name}": {decomp_err}') from decomp_err
                    except zstd.ZstdError as decomp_err:
                        raise InvalidFormatError(f'Decompression failed (zstd) for "{entry_name}": {decomp_err}') from decomp_err
                    except (EOFError, ValueError) as decomp_err:  # Catch potential bz2 errors
                        if compression == "bz2":
                            raise InvalidFormatError(f'Decompression failed (bz2) for "{entry_name}": {decomp_err}') from decomp_err
                        else:  # Re-raise if it wasn't bz2 causing it
                            raise decomp_err
                else:
                    decompressed_data = decrypted_chunk  # Pass through if not compressed

                # 3. Calculate CRC and yield via target function
                if decompressed_data:
                    crc_calculator = zlib.crc32(decompressed_data, crc_calculator)
                    total_extracted_size += len(decompressed_data)
                    target_iterator_func(decompressed_data)

            # --- Finalization ---

            # Finalize decryption (checks authentication tag for GCM)
            if decryptor:
                try:
                    final_decrypted_chunk = decryptor.finalize()
                    # Process the final decrypted chunk through decompressor if needed
                    if decompressor:
                        try:
                            decompressed_data = decompressor.decompress(final_decrypted_chunk)
                        # Corrected: Catch specific zlib/lzma errors and generic EOF/ValueError for bz2
                        except zlib.error as decomp_err:
                            raise InvalidFormatError(f'Decompression failed (zlib) during finalization for "{entry_name}": {decomp_err}') from decomp_err
                        except lzma.LZMAError as decomp_err:
                            raise InvalidFormatError(f'Decompression failed (lzma) during finalization for "{entry_name}": {decomp_err}') from decomp_err
                        except zstd.ZstdError as decomp_err:
                            raise InvalidFormatError(f'Decompression failed (zstd) during finalization for "{entry_name}": {decomp_err}') from decomp_err
                        except (EOFError, ValueError) as decomp_err:  # Catch potential bz2 errors
                            if compression == "bz2":
                                raise InvalidFormatError(f'Decompression failed (bz2) during finalization for "{entry_name}": {decomp_err}') from decomp_err
                            else:
                                raise decomp_err
                    else:
                        decompressed_data = final_decrypted_chunk

                    if decompressed_data:
                        crc_calculator = zlib.crc32(decompressed_data, crc_calculator)
                        total_extracted_size += len(decompressed_data)
                        target_iterator_func(decompressed_data)

                except ValueError as e:  # Catches InvalidTag from finalize()
                    raise DecryptionError(f'Decryption failed for "{entry_name}" (wrong password or data tampered?): {e}') from e

            # Flush the decompressor to get any remaining buffered data
            if decompressor and hasattr(decompressor, "flush") and callable(decompressor.flush):
                # Note: LZMADecompressor doesn't have flush, relies on EOF marker in stream
                # zlib and bz2 might have flush
                try:
                    remaining_decompressed = decompressor.flush()
                    if remaining_decompressed:
                        crc_calculator = zlib.crc32(remaining_decompressed, crc_calculator)
                        total_extracted_size += len(remaining_decompressed)
                        target_iterator_func(remaining_decompressed)
                # Corrected: Catch specific zlib error and generic EOF/ValueError for bz2
                except zlib.error as flush_err:
                    raise InvalidFormatError(f'Decompression flush failed (zlib) for "{entry_name}": {flush_err}') from flush_err
                except (EOFError, ValueError) as flush_err:  # Catch potential bz2 flush errors
                    if compression == "bz2":
                        raise InvalidFormatError(f'Decompression flush failed (bz2) for "{entry_name}": {flush_err}') from flush_err
                    else:
                        raise flush_err  # Re-raise if not bz2

            # Check if LZMA decompression is complete (needs EOF)
            elif isinstance(decompressor, lzma.LZMADecompressor):
                if not decompressor.eof:
                    # This might indicate truncated LZMA stream if no error was raised before
                    print(f'Warning: LZMA stream for "{entry_name}" might be incomplete (EOF not reached).')

        except (IOError, OSError) as e:
            raise HyperspaceUnitError(f'I/O error reading data for "{entry_name}": {e}') from e
        except DecryptionError:  # Re-raise specific decryption errors
            raise
        except InvalidFormatError:  # Re-raise specific format errors
            raise
        except Exception as e:  # Catch other potential errors
            # Clean up stateful objects if possible?
            raise HyperspaceUnitError(f'Error processing data for "{entry_name}": {e}') from e

        # --- Final Verification ---
        # Verify original size
        if total_extracted_size != original_size:
            raise InvalidFormatError(f'Size mismatch after extraction for "{entry_name}": expected {original_size}, got {total_extracted_size}.')

        # Verify CRC32 checksum
        if expected_crc is not None:
            calculated_crc = crc_calculator & 0xFFFFFFFF
            if calculated_crc != (expected_crc & 0xFFFFFFFF):
                raise ChecksumError(f'Checksum mismatch for "{entry_name}": expected {expected_crc}, calculated {calculated_crc}.')

    def extract_data(self, entry_name: str, password: Optional[str] = None) -> bytes:
        """Extracts entry data as bytes."""
        extracted_bytes = io.BytesIO()

        def write_to_bytesio(chunk):
            extracted_bytes.write(chunk)

        self._extract_entry_internal(entry_name, write_to_bytesio, password)
        return extracted_bytes.getvalue()

    def extract_stream(self, entry_name: str, target_stream: BinaryIO, password: Optional[str] = None):
        """Extracts entry data into a writable binary stream."""
        if not hasattr(target_stream, "write"):
            raise TypeError("Target stream object must have a 'write' method.")

        def write_to_stream(chunk):
            target_stream.write(chunk)

        self._extract_entry_internal(entry_name, write_to_stream, password)

    def extract_file(self, entry_name: str, destination_path: str, password: Optional[str] = None):
        """Extracts an entry to the local filesystem."""
        entry_info = self.get_entry_info(entry_name)
        if not entry_info:
            raise EntryNotFoundError(f'Entry not found: "{entry_name}"')

        dest_dir = os.path.dirname(destination_path)
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)

        if entry_info.get("entry_type") == ENTRY_TYPE_DIRECTORY:
            if not os.path.exists(destination_path):
                os.makedirs(destination_path, exist_ok=True)
            elif not os.path.isdir(destination_path):
                raise HyperspaceUnitError(f'Cannot overwrite existing non-directory file with directory: "{destination_path}"')
            if not os.path.isdir(destination_path):  # Check again after potential creation
                print(f"  Created directory: {destination_path}")
        elif entry_info.get("entry_type") == ENTRY_TYPE_FILE:
            try:
                with open(destination_path, "wb") as f_out:
                    self.extract_stream(entry_name, f_out, password)

                if "timestamp" in entry_info:
                    try:
                        os.utime(destination_path, (time.time(), entry_info["timestamp"]))
                    except OSError as e:
                        print(f'Warning: Could not set mod time for "{destination_path}": {e}')

            except (IOError, OSError) as e:
                raise HyperspaceUnitError(f'Failed to write extracted file to "{destination_path}": {e}') from e
        else:
            raise HyperspaceUnitError(f'Unknown entry type for "{entry_name}": {entry_info.get("entry_type")}')

    def extract_all(self, destination_folder: str, password: Optional[str] = None):
        """Extracts all entries into the specified folder."""
        os.makedirs(destination_folder, exist_ok=True)
        extracted_count = 0
        failed_count = 0
        print(f'Extracting all entries to "{destination_folder}"...')
        entry_list = self.list_entries(include_dirs=True)

        def safe_get_info(name):
            try:
                return self.get_entry_info(name)
            except Exception:
                return None

        # Extract directories first
        dir_entries = [e for e in entry_list if safe_get_info(e).get("entry_type") == ENTRY_TYPE_DIRECTORY]
        file_entries = [e for e in entry_list if safe_get_info(e).get("entry_type") == ENTRY_TYPE_FILE]

        for entry_name in dir_entries + file_entries:
            relative_path = entry_name.replace("/", os.sep)
            target_path = os.path.join(destination_folder, relative_path)
            entry_info = safe_get_info(entry_name)
            is_dir = entry_info.get("entry_type") == ENTRY_TYPE_DIRECTORY if entry_info else False

            try:
                if not (is_dir and os.path.isdir(target_path)):
                    print(f"  Extracting: {entry_name} -> {target_path}")
                self.extract_file(entry_name, target_path, password)
                extracted_count += 1
            except (EntryNotFoundError, ChecksumError, DecryptionError, HyperspaceUnitError, PermissionError, IsADirectoryError) as e:
                print(f'  -> Failed to extract "{entry_name}": {e}')
                failed_count += 1
            except Exception as e:
                print(f'  -> Unexpected error extracting "{entry_name}": {e}')
                failed_count += 1

        print(f"Extraction complete. {extracted_count} entries processed, {failed_count} failed.")
        if failed_count > 0:
            pass

    def list_entries(self, include_dirs: bool = False) -> List[str]:
        """Returns a list of active entry names."""
        if not self._file or self._file.closed:
            try:
                with HyperspaceUnit(self.filename) as temp_unit:
                    temp_unit.open("r")
                    return temp_unit.list_entries(include_dirs=include_dirs)
            except (FileNotFoundError, InvalidFormatError, HyperspaceUnitError):
                return []

        entries = []
        for name, meta in self._index.items():
            if not meta.get("deleted", False):
                if include_dirs or meta.get("entry_type", ENTRY_TYPE_FILE) == ENTRY_TYPE_FILE:
                    entries.append(name)
        return sorted(entries)

    def get_entry_info(self, entry_name: str) -> Optional[Dict[str, Any]]:
        """Returns the metadata dictionary for a specific active entry."""
        entry_name = entry_name.strip("/")
        if not self._file or self._file.closed:
            try:
                with HyperspaceUnit(self.filename) as temp_unit:
                    temp_unit.open("r")
                    return temp_unit.get_entry_info(entry_name)
            except (FileNotFoundError, InvalidFormatError, HyperspaceUnitError):
                return None

        info = self._index.get(entry_name)
        if info and not info.get("deleted", False):
            return info.copy()
        return None

    def remove_entry(self, entry_name: str, permanent: bool = False):
        """Removes an entry (lazy or permanent via compact)."""
        if not self._file or self._file.closed or "w" in self._open_mode or "+" not in self._open_mode:
            raise HyperspaceUnitError('Unit must be open in append ("a") or read/write ("r+") mode to remove entries.')

        entry_name = entry_name.strip("/")
        if self.get_entry_info(entry_name) is None:
            raise EntryNotFoundError(f'Entry not found or already deleted: "{entry_name}"')

        if permanent:
            print(f'Performing permanent removal of "{entry_name}" by compacting...')
            self._index[entry_name]["deleted"] = True
            self._modified = True
            self.compact()
        else:
            self._index[entry_name]["deleted"] = True
            self._modified = True
            print(f'Entry "{entry_name}" marked for deletion. Run compact() to reclaim space.')

    def update_data(self, entry_name: str, data: bytes, compress_algo: Optional[str] = DEFAULT_COMPRESSION_ALGO, timestamp: Optional[float] = None, metadata: Optional[Dict[str, Any]] = None, password: Optional[str] = None):
        """Updates an existing entry by marking old as deleted and adding new."""
        if self.get_entry_info(entry_name) is None:
            raise EntryNotFoundError(f'Cannot update non-existent entry: "{entry_name}"')
        self.remove_entry(entry_name, permanent=False)
        self.add_data(entry_name, data, compress_algo, timestamp, metadata, password)

    def update_file(self, file_path: str, entry_name: Optional[str] = None, compress_algo: Optional[str] = DEFAULT_COMPRESSION_ALGO, metadata: Optional[Dict[str, Any]] = None, password: Optional[str] = None):
        """Updates an existing entry with data from a local file."""
        if entry_name is None:
            entry_name = os.path.basename(file_path)
        entry_name = entry_name.replace(os.sep, "/").strip("/")
        if self.get_entry_info(entry_name) is None:
            raise EntryNotFoundError(f'Cannot update non-existent entry: "{entry_name}"')
        self.remove_entry(entry_name, permanent=False)
        self.add_file(file_path, entry_name, compress_algo, metadata, password)

    def update_stream(self, entry_name: str, stream: BinaryIO, original_size: int, compress_algo: Optional[str] = DEFAULT_COMPRESSION_ALGO, timestamp: Optional[float] = None, metadata: Optional[Dict[str, Any]] = None, password: Optional[str] = None):
        """Updates an existing entry with data from a stream."""
        if self.get_entry_info(entry_name) is None:
            raise EntryNotFoundError(f'Cannot update non-existent entry: "{entry_name}"')
        self.remove_entry(entry_name, permanent=False)
        self.add_stream(entry_name, stream, original_size, compress_algo, timestamp, metadata, password)

    def compact(self, target_filename: Optional[str] = None):
        """Rewrites the unit, excluding deleted entries."""
        if not self._file or self._file.closed:
            raise HyperspaceUnitError("Unit must be open to compact.")
        if "r" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError("Read access required for compaction.")

        is_inplace = target_filename is None
        if is_inplace:
            if "+" not in self._open_mode:
                raise HyperspaceUnitError("Write access ('a' or 'r+') required for in-place compaction.")
            temp_filename = self.filename + ".compact_tmp"
            final_filename = self.filename
        else:
            temp_filename = target_filename + ".compact_tmp"
            final_filename = target_filename

        print(f"Starting compaction{' (in-place)' if is_inplace else f' to {final_filename}'}...")
        new_index: Dict[str, Dict[str, Any]] = {}
        current_offset = HEADER_SIZE

        try:
            with open(temp_filename, "wb") as temp_f:
                temp_f.write(
                    struct.pack(
                        HEADER_FORMAT,
                        MAGIC_NUMBER,
                        FORMAT_VERSION,
                        0,  # Flags
                        0,  # Metadata Offset
                        0,  # Metadata Size,
                        0,  # Index Offset,
                        0,  # Index Size,
                        0,  # Index CRC32,
                    )
                )

                current_offset = HEADER_SIZE
                new_index: Dict[str, Dict[str, Any]] = {}
                new_archive_metadata = self._archive_metadata.copy()

                active_entry_names = sorted([name for name, meta in self._index.items() if not meta.get("deleted", False)])

                for entry_name in active_entry_names:
                    entry_info = self._index[entry_name]
                    print(f"  Processing: {entry_name} ({entry_info.get('entry_type', 'file')})...")

                    if entry_info.get("entry_type") == ENTRY_TYPE_DIRECTORY:
                        new_index[entry_name] = entry_info.copy()
                        continue

                    # --- Copy File Data ---
                    self._file.seek(entry_info["offset"])
                    bytes_to_copy = entry_info["stored_size"]
                    bytes_copied = 0
                    temp_f.seek(current_offset)
                    new_entry_offset = current_offset

                    while bytes_copied < bytes_to_copy:
                        read_size = min(CHUNK_SIZE, bytes_to_copy - bytes_copied)
                        chunk = self._file.read(read_size)
                        if not chunk:
                            break
                        temp_f.write(chunk)
                        bytes_copied += len(chunk)

                    if bytes_copied != bytes_to_copy:
                        raise HyperspaceUnitError(f'Read error during compaction for "{entry_name}". Expected {bytes_to_copy}, got {bytes_copied}.')

                    new_entry_info = entry_info.copy()
                    new_entry_info["offset"] = new_entry_offset
                    new_index[entry_name] = new_entry_info
                    current_offset += bytes_copied

                # --- Write the new archive metadata ---
                temp_f.seek(current_offset)

                metadata_offset = 0
                metadata_size = 0
                if new_archive_metadata:
                    try:
                        metadata_json = json.dumps(new_archive_metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                        compressed_metadata = zlib.compress(metadata_json, level=DEFAULT_COMPRESSION_LEVEL["zlib"])
                        metadata_offset = temp_f.tell()
                        metadata_size = len(compressed_metadata)
                        temp_f.write(compressed_metadata)
                    except Exception as e_meta:
                        raise HyperspaceUnitError(f"Failed to serialize or compress the metadata block: {e_meta}") from e_meta
                    except (IOError, OSError) as e_meta:
                        raise HyperspaceUnitError(f"I/O error while writing metadata block: {e_meta}") from e_meta

                index_pos = temp_f.tell()
                index_size = 0
                index_crc32 = 0
                if new_index:
                    try:
                        index_json = json.dumps(new_index, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                        compressed_index = zlib.compress(index_json, level=DEFAULT_COMPRESSION_LEVEL["zlib"])
                        index_size = len(compressed_index)
                        index_crc32 = zlib.crc32(compressed_index) & 0xFFFFFFFF
                        temp_f.write(compressed_index)
                    except Exception as e_index:
                        raise HyperspaceUnitError(f"Failed to serialize or compress the index: {e_index}") from e_index
                    except (IOError, OSError) as e_index:
                        raise HyperspaceUnitError(f"I/O error while writing index: {e_index}") from e_index

                # --- Write the final header ---
                temp_f.seek(0)
                final_header = struct.pack(
                    HEADER_FORMAT,
                    MAGIC_NUMBER,
                    FORMAT_VERSION,
                    0,  # Flags
                    metadata_offset,
                    metadata_size,
                    index_pos,
                    index_size,
                    index_crc32,
                )
                temp_f.write(final_header)

            # --- Replace original file ---
            if is_inplace:
                original_file_handle = self._file
                self._file = None
                original_file_handle.close()
                try:
                    import shutil

                    shutil.move(temp_filename, final_filename)
                except OSError:
                    try:
                        os.remove(final_filename)
                        os.rename(temp_filename, final_filename)
                    except OSError as e_rep:
                        raise HyperspaceUnitError(f"Failed to replace original file during compaction: {e_rep}") from e_rep
                self.open(self._open_mode)
            else:
                os.replace(temp_filename, final_filename)

            self._index = new_index
            self._modified = False
            print("Compaction finished successfully.")

        except Exception as e:
            if os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except OSError:
                    pass
            if is_inplace and (not self._file or self._file.closed):
                try:
                    self.open(self._open_mode)
                except Exception as reopen_e:
                    print(f"Warning: Could not reopen original file after failed compaction: {reopen_e}")
            raise HyperspaceUnitError(f"Compaction failed: {e}") from e

    def test_unit(self, password: Optional[str] = None) -> List[Tuple[str, str]]:
        """
        Tests the integrity of the archive by attempting to read and verify each entry.

        Checks CRC32, original size, and decryption (if password provided).

        Args:
            password: The password for decryption, if entries are encrypted.

        Returns:
            A list of tuples `(entry_name, error_message)` for entries that failed verification.
            Returns an empty list if all entries are okay.
        """

        if not self._file or self._file.closed:
            try:
                self.open("r")
            except Exception as e:
                raise HyperspaceUnitError(f"Unit must be open for reading. Failed to reopen: {e}") from e
        if "r" not in self._open_mode and "+" not in self._open_mode:
            raise HyperspaceUnitError("Unit must be open in a readable mode ('r' or 'r+') to test.")

        print(f"Testing integrity of '{self.filename}'...")
        failed_entries: List[Tuple[str, str]] = []
        entries_to_test = self.list_entries()

        for entry_name in entries_to_test:
            print(f"   Testing: {entry_name}...", end="", flush=True)
            try:
                self._extract_entry_internal(
                    entry_name=entry_name,
                    target_iterator_func=lambda chunk: None,
                    password=password,
                )
                print(" OK")
            except (ChecksumError, DecryptionError, InvalidFormatError, EntryNotFoundError, HyperspaceUnitError) as e:
                error_msg = f"{type(e).__name__}: {e}"
                print(f" FAILED: {error_msg}")
                failed_entries.append((entry_name, error_msg))
            except Exception as e:
                error_msg = f"Unexpected error: {type(e).__name__}: {e}"
                print(f" FAILED: {error_msg}")
                failed_entries.append((entry_name, error_msg))

        if not failed_entries:
            print("Integrity test passed for all entries.")
        else:
            print(f"Integrity test failed for {len(failed_entries)} entries.")

        return failed_entries


# --- Example Usage ---
if __name__ == "__main__":
    print("--- HyperspaceUnit Demo ---")
    UNIT_FILENAME = "demo_unit.hsu"
    EXTRACT_FOLDER = "demo_extract"
    DEMO_PASSWORD = "supersecretpassword"  # Use a strong password in real apps!

    # Clean up previous runs
    if os.path.exists(UNIT_FILENAME):
        os.remove(UNIT_FILENAME)
    if os.path.exists(EXTRACT_FOLDER):
        import shutil

        shutil.rmtree(EXTRACT_FOLDER)
    if os.path.exists("temp_files"):
        import shutil

        shutil.rmtree("temp_files")

    # Create dummy files
    os.makedirs("temp_files/docs", exist_ok=True)
    os.makedirs("temp_files/images", exist_ok=True)
    with open("temp_files/docs/report.txt", "w") as f:
        f.write("Sensitive report data.")
    with open("temp_files/images/logo.png", "wb") as f:
        f.write(os.urandom(5000))  # ~50KB
    with open("temp_files/large_log.log", "w") as f:
        f.write("Log line\n" * 10000)  # ~100KB
    with open("temp_files/large_log.zst", "wb") as f:
        f.write(os.urandom(5000))  # ~50KB

    # 1. Create and add entries (with encryption, metadata, directories)
    try:
        with HyperspaceUnit(UNIT_FILENAME).open("w") as unit:
            # Add metadata
            unit.set_archive_metadata({"creator": "DemoScript", "comment": "HSU (Hyperspace Unit) Test Archive", "created_utc": time.time()})
            print("  - Set archive metadata.")

            # Add directory
            unit.add_directory("confidential/", metadata={"access_level": "admin"})
            print("  - Added directory confidential/")

            # Add encrypted file with metadata
            unit.add_file("temp_files/docs/report.txt", "confidential/secret_report.txt", password=DEMO_PASSWORD, compress_algo="zlib", metadata={"author": "Astro", "tags": ["report", "urgent"]})
            print("  - Added encrypted confidential/secret_report.txt")

            # Add unencrypted image with different compression
            unit.add_file("temp_files/images/logo.png", "assets/images/logo.png", compress_algo="bz2", metadata={"dimensions": "128x128"})
            print("  - Added assets/images/logo.png (bz2 compressed)")

            # Add large file using streaming (demonstration)
            with open("temp_files/large_log.log", "rb") as log_stream:
                unit.add_stream(
                    "logs/large_app.log",
                    log_stream,
                    os.path.getsize("temp_files/large_log.log"),
                    compress_algo="lzma",  # Use lzma for potentially better compression
                )
            print("  - Added logs/large_app.log via stream (lzma compressed)")

            # Add file using Zstandard
            with open("temp_files/large_log.zst", "rb") as zstd_stream:
                unit.add_stream(
                    "logs/large_app.zst",
                    zstd_stream,
                    os.path.getsize("temp_files/large_log.zst"),
                    compress_algo="zstd",
                )
            print("  - Added logs/large_app.zst via stream (zstd compressed)")

            small_data = b"abc"
            unit.add_data("misc/small.txt", small_data, compress_algo="zlib", allow_ineffective_compression=True)
            print(f"  - Added misc/small.txt (size {len(small_data)}) with zlib (ineffective allowed)")
            # If allow_ineffective_compression=False, this would fail.

        print(f'"{UNIT_FILENAME}" created.')
    except Exception as e:
        print(f"Error during creation: {e}")
        raise

    # 2. List and inspect entries
    print(f'\n2. Listing entries in "{UNIT_FILENAME}"...')
    try:
        with HyperspaceUnit(UNIT_FILENAME).open("r") as unit:
            print("  Metadata:")
            archive_metadata = unit.get_archive_metadata()
            for k, v in archive_metadata.items():
                print(f"    {k}: {v}")

            print("  All entries (including dirs):")
            for entry in unit.list_entries(include_dirs=True):
                info = unit.get_entry_info(entry)
                if not info:
                    print(f"    - {entry} [Error retrieving info]")
                    continue
                entry_type = info.get("entry_type", "file")
                print(f"    - {entry} [{entry_type}]")
                if entry_type == "file":
                    comp = info.get("compression")
                    enc = "encrypted" if "encryption" in info else "plain"
                    print(f"      (Size: {info.get('orig_size')}, Stored: {info.get('stored_size')}, Comp: {comp}, {enc})")
                if info.get("metadata"):
                    print(f"      Metadata: {info['metadata']}")

            # Get specific info
            report_info = unit.get_entry_info("confidential/secret_report.txt")
            if report_info and "encryption" in report_info:
                print("\n  Encryption info for secret_report.txt:")
                enc_meta = report_info["encryption"]
                print(f"    Algo: {enc_meta.get('algo')}")
                print(f"    Salt: {enc_meta.get('salt')[:8]}...")
                print(f"    Nonce: {enc_meta.get('nonce')[:8]}...")
                print(f"    Tag: {enc_meta.get('tag')[:8]}...")

    except Exception as e:
        print(f"Error during listing: {e}")
        raise

    # 3. Test integrity of the archive
    try:
        with HyperspaceUnit(UNIT_FILENAME).open("r") as unit:
            # Test without password (expecting decryption failure)
            print("  Testing without password (expecting decryption failure):")
            failures_no_pass = unit.test_unit()
            # assert any("secret_report.txt" in f[0] for f in failures_no_pass)  # Check for failure

            print("\n  Testing with correct password:")
            failures_with_pass = unit.test_unit(password=DEMO_PASSWORD)  # Test with password
            if not failures_with_pass:
                print("  -> Test with password successful!")
            else:
                print(f"  -> Test with password FAILED for: {failures_with_pass}")

    except Exception as e:
        print(f"Error during testing: {e}")

    # 4. Extract entries
    print(f'\n3. Extracting entries to "{EXTRACT_FOLDER}"...')
    try:
        with HyperspaceUnit(UNIT_FILENAME).open("r") as unit:
            try:
                print("  Attempting extract_all without password (expect failure for encrypted)...")
                unit.extract_all(EXTRACT_FOLDER)
            except DecryptionError as e:
                print(f"  -> Expected failure: {e}")

            print("\n  Attempting extract_all WITH password...")
            unit.extract_all(EXTRACT_FOLDER, password=DEMO_PASSWORD)

        # Verify extracted content (simple check)
        extracted_report_path = os.path.join(EXTRACT_FOLDER, "confidential", "secret_report.txt")
        if os.path.exists(extracted_report_path):
            with open(extracted_report_path, "r") as f:
                content = f.read()
            print(f'\n  Content of extracted secret_report.txt: "{content}"')
            if content == "Sensitive report data.":
                print("  -> Decryption successful!")
            else:
                print("  -> Decryption FAILED or content mismatch!")
        else:
            print(f"  -> ERROR: {extracted_report_path} was not extracted!")

        extracted_dir_path = os.path.join(EXTRACT_FOLDER, "confidential")
        if os.path.isdir(extracted_dir_path):
            print(f"  -> Directory {extracted_dir_path} created successfully.")

    except Exception as e:
        print(f"Error during extraction: {e}")
        raise

    # 5. Update an entry
    print("\n4. Updating 'assets/images/logo.png'...")
    try:
        # Create new dummy data for update
        with open("temp_files/new_logo.png", "wb") as f:
            f.write(os.urandom(100))

        with HyperspaceUnit(UNIT_FILENAME).open("a") as unit:
            unit.update_file(
                "temp_files/new_logo.png",
                "assets/images/logo.png",  # Same entry name
                compress_algo="none",  # Change compression
                metadata={"dimensions": "32x32", "updated": True},  # Update metadata
            )
        print("  Entry updated (old marked deleted, new added).")

        # Verify update
        with HyperspaceUnit(UNIT_FILENAME).open("r") as unit:
            info = unit.get_entry_info("assets/images/logo.png")
            if info:
                print("\n  Info after update:")
                print(f"    Orig Size: {info.get('orig_size')}")  # Should be 100
                print(f"    Compression: {info.get('compression')}")  # Should be none
                print(f"    Metadata: {info.get('metadata')}")  # Should show updated
            else:
                print("  -> ERROR: Updated entry not found!")

    except Exception as e:
        print(f"Error during update: {e}")
        raise

    # 6. Compact to remove deleted/old entries
    print(f'\n5. Compacting "{UNIT_FILENAME}"...')
    try:
        size_before = os.path.getsize(UNIT_FILENAME)
        with HyperspaceUnit(UNIT_FILENAME).open("a") as unit:
            unit.compact()
        size_after = os.path.getsize(UNIT_FILENAME)
        print(f"  Size before: {size_before}, Size after: {size_after}")
        if size_after < size_before:
            print("  -> Compaction reduced size.")
        else:
            print("  -> Compaction did not reduce size significantly.")
    except Exception as e:
        print(f"Error during compaction: {e}")
        raise

    # Clean up
    if os.path.exists("temp_files"):
        import shutil

        shutil.rmtree("temp_files")
    # Keep UNIT_FILENAME and EXTRACT_FOLDER for inspection

    print("\n--- Demo Finished ---")
