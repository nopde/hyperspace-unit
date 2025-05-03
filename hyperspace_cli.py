# -*- coding: utf-8 -*-
"""
hyperspace_cli.py

Command Line Interface (CLI) for managing Hyperspace Unit (.hsu) files.

Uses the hyperspace_unit module to perform operations like creating units,
adding files, listing contents, extracting, and more.
"""

import argparse
import os
import sys
import getpass
import datetime
from hyperspace_unit import (
    HyperspaceUnit,
    EntryNotFoundError,
    ChecksumError,
    InvalidFormatError,
    DecryptionError,
    FeatureNotAvailableError,
    HyperspaceUnitError,
    SUPPORTED_COMPRESSION,
    ENTRY_TYPE_DIRECTORY,
    ENTRY_TYPE_FILE,
    DEFAULT_COMPRESSION_ALGO
)

# --- Command Functions ---


def handle_create(args):
    """Handles the 'create' command."""
    # 'create' is implicitly handled by opening in 'w' mode.
    # This function mainly exists for structure, but we can add
    # checks or specific creation options later if needed.
    try:
        # Just opening in 'w' mode creates/truncates the file.
        with HyperspaceUnit(args.unit_file).open("w") as _:
            print(f'Hyperspace Unit "{args.unit_file}" created successfully (or overwritten).')
            # Optionally add default entries or metadata here if desired
            # unit.add_directory(".info")
            # unit.add_data(".info/creation_time", str(time.time()).encode())
    except HyperspaceUnitError as e:
        print(f'Error creating unit "{args.unit_file}": {e}', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during creation: {e}", file=sys.stderr)
        sys.exit(1)


def handle_add(args):
    """Handles the 'add' command."""
    password = None
    if args.password:
        password = getpass.getpass("Enter password for encryption (optional, press Enter to skip): ")
        if not password:  # User pressed Enter without typing
            password = None
            print("No password provided, adding unencrypted.")

    try:
        # Open in append ('a') mode to add to existing or create new
        with HyperspaceUnit(args.unit_file).open("a") as unit:
            for item_path in args.paths:
                entry_name = None
                # Check if a custom entry name is provided like 'local/path:archive/path'
                if ":" in item_path and not os.path.exists(item_path):
                    try:
                        local_path, archive_path = item_path.split(":", 1)
                        entry_name = archive_path.replace(os.sep, "/").strip("/")
                        item_path = local_path  # Use the local path for os checks
                    except ValueError:
                        # Treat as a normal path if split fails unexpectedly
                        entry_name = None

                if not os.path.exists(item_path):
                    print(f'Warning: Path not found, skipping: "{item_path}"', file=sys.stderr)
                    continue

                # Determine archive name if not specified via ':' syntax
                if entry_name is None:
                    archive_name_base = os.path.basename(item_path) if item_path != "." else os.path.basename(os.getcwd())
                    # Prepend parent directory if specified and not adding root
                    if args.parent_dir and item_path != ".":
                        parent = os.path.basename(os.path.dirname(os.path.abspath(item_path)))
                        if parent:
                            archive_name_base = os.path.join(parent, archive_name_base).replace(os.sep, "/")
                    entry_name = archive_name_base

                if os.path.isdir(item_path):
                    # Add directory entry explicitly
                    print(f'Adding directory: "{item_path}" as "{entry_name}/"')
                    # Ensure directory names end with a slash in the archive
                    if not entry_name.endswith("/"):
                        entry_name += "/"
                    unit.add_directory(entry_name, timestamp=os.path.getmtime(item_path))
                    # Recursive add if specified (TODO: Implement recursive add)
                    if args.recursive:
                        print("Recursive add for directories is not yet implemented.", file=sys.stderr)

                elif os.path.isfile(item_path):
                    print(f'Adding file: "{item_path}" as "{entry_name}" (Compression: {args.compress}, Encrypted: {bool(password)})')
                    unit.add_file(item_path, entry_name=entry_name, compress_algo=args.compress, password=password)
                else:
                    print(f'Warning: Path is not a file or directory, skipping: "{item_path}"', file=sys.stderr)

            print(f'Finished adding entries to "{args.unit_file}".')

    except FeatureNotAvailableError as e:
        print(f"Error: {e}. Is the 'cryptography' library installed?", file=sys.stderr)
        sys.exit(1)
    except HyperspaceUnitError as e:
        print(f'Error adding to unit "{args.unit_file}": {e}', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during add: {e}", file=sys.stderr)
        sys.exit(1)


def handle_list(args):
    """Handles the 'list' command."""
    try:
        with HyperspaceUnit(args.unit_file).open("r") as unit:
            entries = unit.list_entries(include_dirs=True)
            if not entries:
                print(f'Hyperspace Unit "{args.unit_file}" is empty or contains no active entries.')
                return

            print(f'Contents of "{args.unit_file}":')
            if args.long:
                # Detailed listing
                print(f"{'Type':<6} {'Size':>12} {'Stored':>12} {'Comp':<6} {'Enc':<4} {'Timestamp':<26} {'Name'}")
                print("-" * 80)
                for entry_name in entries:
                    info = unit.get_entry_info(entry_name)
                    if not info:
                        continue  # Should not happen if list_entries is correct
                    entry_type = info.get("entry_type", ENTRY_TYPE_FILE)
                    orig_size = info.get("orig_size", 0)
                    stored_size = info.get("stored_size", 0)
                    comp = info.get("compression", "none")
                    encrypted = "Yes" if "encryption" in info else "No"
                    ts = datetime.datetime.fromtimestamp(info.get("timestamp", 0), datetime.timezone.utc).isoformat()

                    type_str = "Dir" if entry_type == ENTRY_TYPE_DIRECTORY else "File"
                    print(f"{type_str:<6} {orig_size:>12} {stored_size:>12} {comp:<6} {encrypted:<4} {ts:<26} {entry_name}")
                    if args.metadata and info.get("metadata"):
                        print(f"  Metadata: {info['metadata']}")

            else:
                # Simple listing
                for entry_name in entries:
                    print(entry_name)

    except FileNotFoundError:
        print(f'Error: Hyperspace Unit "{args.unit_file}" not found.', file=sys.stderr)
        sys.exit(1)
    except InvalidFormatError as e:
        print(f'Error: "{args.unit_file}" is not a valid Hyperspace Unit or is corrupted. {e}', file=sys.stderr)
        sys.exit(1)
    except HyperspaceUnitError as e:
        print(f'Error listing unit "{args.unit_file}": {e}', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during list: {e}", file=sys.stderr)
        sys.exit(1)


def handle_extract(args):
    """Handles the 'extract' command."""
    password = None
    # Check if any entry might be encrypted before asking for password
    needs_password = False
    try:
        with HyperspaceUnit(args.unit_file).open("r") as unit:
            # Rough check: iterate through info of entries to extract
            entries_to_check = args.entries if args.entries else unit.list_entries()
            for entry_name in entries_to_check:
                info = unit.get_entry_info(entry_name)
                if info and "encryption" in info:
                    needs_password = True
                    break
    except Exception:
        # Ignore errors here, we'll handle them properly during extraction
        pass

    if needs_password:
        password = getpass.getpass("Enter password for decryption (required for some entries): ")
        if not password:
            print("Warning: No password provided. Encrypted files may fail to extract.", file=sys.stderr)
            # Allow proceeding without password, extract_all/extract_file will handle errors

    try:
        with HyperspaceUnit(args.unit_file).open("r") as unit:
            destination = args.destination if args.destination else "."  # Default to current dir

            if args.entries:
                # Extract specific entries
                print(f'Extracting specific entries to "{destination}"...')
                os.makedirs(destination, exist_ok=True)  # Ensure base dir exists
                extracted_count = 0
                failed_count = 0
                for entry_name in args.entries:
                    target_path = os.path.join(destination, entry_name.replace("/", os.sep))
                    try:
                        print(f"  Extracting: {entry_name} -> {target_path}")
                        unit.extract_file(entry_name, target_path, password=password)
                        extracted_count += 1
                    except EntryNotFoundError:
                        print(f'  -> Error: Entry "{entry_name}" not found in the unit.', file=sys.stderr)
                        failed_count += 1
                    except DecryptionError as e:
                        print(f'  -> Error extracting "{entry_name}": {e}. Incorrect password?', file=sys.stderr)
                        failed_count += 1
                    except (ChecksumError, InvalidFormatError, HyperspaceUnitError, PermissionError, IsADirectoryError) as e:
                        print(f'  -> Error extracting "{entry_name}": {e}', file=sys.stderr)
                        failed_count += 1
                    except Exception as e:
                        print(f'  -> Unexpected error extracting "{entry_name}": {e}', file=sys.stderr)
                        failed_count += 1
                print(f"Extraction finished. {extracted_count} entries extracted, {failed_count} failed.")
                if failed_count > 0:
                    sys.exit(1)  # Exit with error if any extraction failed

            else:
                # Extract all
                unit.extract_all(destination, password=password)  # extract_all prints its own summary

    except FileNotFoundError:
        print(f'Error: Hyperspace Unit "{args.unit_file}" not found.', file=sys.stderr)
        sys.exit(1)
    except InvalidFormatError as e:
        print(f'Error: "{args.unit_file}" is not a valid Hyperspace Unit or is corrupted. {e}', file=sys.stderr)
        sys.exit(1)
    except FeatureNotAvailableError as e:
        print(f"Error: {e}. Is the 'cryptography' library installed?", file=sys.stderr)
        sys.exit(1)
    except HyperspaceUnitError as e:
        print(f'Error during extraction from "{args.unit_file}": {e}', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during extraction: {e}", file=sys.stderr)
        sys.exit(1)


def handle_remove(args):
    """Handles the 'remove' command."""
    try:
        # Open in append ('a') mode which allows modification
        with HyperspaceUnit(args.unit_file).open("a") as unit:
            removed_count = 0
            failed_count = 0
            for entry_name in args.entries:
                try:
                    unit.remove_entry(entry_name, permanent=args.permanent)
                    action = "Permanently removed" if args.permanent else "Marked for deletion"
                    print(f'{action}: "{entry_name}"')
                    removed_count += 1
                except EntryNotFoundError:
                    print(f'Warning: Entry "{entry_name}" not found or already deleted.', file=sys.stderr)
                    failed_count += 1
                except HyperspaceUnitError as e:
                    print(f'Error removing "{entry_name}": {e}', file=sys.stderr)
                    failed_count += 1
                except Exception as e:
                    print(f'Unexpected error removing "{entry_name}": {e}', file=sys.stderr)
                    failed_count += 1

            if removed_count > 0 and not args.permanent:
                print("Run 'compact' command to permanently remove data and reclaim space.")
            elif removed_count == 0 and failed_count == 0:
                print("No entries specified or found to remove.")

            if failed_count > 0:
                sys.exit(1)

    except FileNotFoundError:
        print(f'Error: Hyperspace Unit "{args.unit_file}" not found.', file=sys.stderr)
        sys.exit(1)
    except InvalidFormatError as e:
        print(f'Error: "{args.unit_file}" is not a valid Hyperspace Unit or is corrupted. {e}', file=sys.stderr)
        sys.exit(1)
    except HyperspaceUnitError as e:
        print(f'Error opening unit "{args.unit_file}" for removal: {e}', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during remove: {e}", file=sys.stderr)
        sys.exit(1)


def handle_compact(args):
    """Handles the 'compact' command."""
    target = args.output if args.output else None
    action = f'to "{target}"' if target else "in-place"
    print(f'Compacting Hyperspace Unit "{args.unit_file}" {action}...')

    try:
        # Open in 'a' mode for potential in-place compaction
        with HyperspaceUnit(args.unit_file).open("a") as unit:
            unit.compact(target_filename=target)
        print("Compaction successful.")
    except FileNotFoundError:
        print(f'Error: Hyperspace Unit "{args.unit_file}" not found.', file=sys.stderr)
        sys.exit(1)
    except InvalidFormatError as e:
        print(f'Error: "{args.unit_file}" is not a valid Hyperspace Unit or is corrupted. {e}', file=sys.stderr)
        sys.exit(1)
    except HyperspaceUnitError as e:
        print(f"Error during compaction: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during compaction: {e}", file=sys.stderr)
        sys.exit(1)


# --- Main Execution ---


def main():
    parser = argparse.ArgumentParser(description="Hyperspace Unit CLI - Manage .hsu container files.", epilog="Example: hyperspace add my_unit.hsu file1.txt docs/ -c lzma -p")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- Create Command ---
    parser_create = subparsers.add_parser("create", help="Create a new (or overwrite an existing) Hyperspace Unit.")
    parser_create.add_argument("unit_file", help="Path to the .hsu file to create.")
    parser_create.set_defaults(func=handle_create)

    # --- Add Command ---
    parser_add = subparsers.add_parser("add", help="Add files or directories to a Hyperspace Unit.")
    parser_add.add_argument("unit_file", help="Path to the .hsu file.")
    parser_add.add_argument("paths", nargs="+", help="Local file(s) or director(y/ies) to add. Use 'local:archive' syntax to specify archive name.")
    parser_add.add_argument("-c", "--compress", choices=SUPPORTED_COMPRESSION, default=DEFAULT_COMPRESSION_ALGO, help=f"Compression algorithm (default: {DEFAULT_COMPRESSION_ALGO}).")
    parser_add.add_argument("-p", "--password", action="store_true", help="Prompt for password to encrypt added files.")
    parser_add.add_argument("-r", "--recursive", action="store_true", help="Recursively add contents of directories (NOT YET IMPLEMENTED).")
    parser_add.add_argument("--parent-dir", action="store_true", help="Include parent directory name in the archive path.")
    parser_add.set_defaults(func=handle_add)

    # --- List Command ---
    parser_list = subparsers.add_parser("list", help="List contents of a Hyperspace Unit.")
    parser_list.add_argument("unit_file", help="Path to the .hsu file.")
    parser_list.add_argument("-l", "--long", action="store_true", help="Show detailed listing.")
    parser_list.add_argument("-m", "--metadata", action="store_true", help="Show custom metadata in long listing.")
    parser_list.set_defaults(func=handle_list)

    # --- Extract Command ---
    parser_extract = subparsers.add_parser("extract", help="Extract entries from a Hyperspace Unit.")
    parser_extract.add_argument("unit_file", help="Path to the .hsu file.")
    parser_extract.add_argument("entries", nargs="*", help="Specific entry names to extract (default: extract all).")
    parser_extract.add_argument("-d", "--destination", help="Directory to extract files to (default: current directory).")
    # Password prompt is handled within the function based on whether encrypted files are encountered
    parser_extract.set_defaults(func=handle_extract)

    # --- Remove Command ---
    parser_remove = subparsers.add_parser("remove", help="Remove entries from a Hyperspace Unit.")
    parser_remove.add_argument("unit_file", help="Path to the .hsu file.")
    parser_remove.add_argument("entries", nargs="+", help="Entry names to remove.")
    parser_remove.add_argument("--permanent", action="store_true", help="Permanently remove data by compacting (can be slow). Default is lazy delete.")
    parser_remove.set_defaults(func=handle_remove)

    # --- Compact Command ---
    parser_compact = subparsers.add_parser("compact", help="Reclaim space by removing deleted entries.")
    parser_compact.add_argument("unit_file", help="Path to the .hsu file to compact.")
    parser_compact.add_argument("-o", "--output", help="Write compacted unit to a new file instead of in-place.")
    parser_compact.set_defaults(func=handle_compact)

    # --- Parse Arguments ---
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()

    # --- Execute Command ---
    args.func(args)


if __name__ == "__main__":
    main()
