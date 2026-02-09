#!/usr/bin/env python3
"""
CSV Sorter - Sort CSV files by selected columns with intelligent data type handling
"""

import csv
import sys
import argparse
import re
from datetime import datetime
from pathlib import Path


def parse_date(date_string):
    """
    Parse date string in various formats.
    Handles formats like "March 16th 2025, 23:44:35.216"
    """
    # Remove ordinal suffixes (st, nd, rd, th) more comprehensively
    cleaned = re.sub(r'(\d+)(st|nd|rd|th)', r'\1', date_string)
    
    # Try various date formats
    date_formats = [
        "%B %d %Y, %H:%M:%S.%f",  # March 16 2025, 23:44:35.216
        "%B %d %Y, %H:%M:%S",      # March 16 2025, 23:44:35
        "%Y-%m-%d %H:%M:%S.%f",    # 2025-03-16 23:44:35.216
        "%Y-%m-%d %H:%M:%S",       # 2025-03-16 23:44:35
        "%Y-%m-%d",                # 2025-03-16
        "%m/%d/%Y",                # 03/16/2025
        "%d/%m/%Y",                # 16/03/2025
        "%B %d, %Y",               # March 16, 2025
        "%m/%d/%Y %H:%M:%S",       # 03/16/2025 14:30:00
        "%d/%m/%Y %H:%M:%S",       # 16/03/2025 14:30:00
    ]
    
    for fmt in date_formats:
        try:
            return datetime.strptime(cleaned.strip(), fmt)
        except ValueError:
            continue
    
    # If no format matches, return None
    return None


def detect_column_type(values):
    """
    Detect the data type of a column based on its values.
    Returns: 'date', 'numeric', or 'text'
    """
    # Sample up to 100 non-empty values for type detection
    sample = [v for v in values if v.strip()][:100]
    
    if not sample:
        return 'text'
    
    # Check if dates
    date_count = sum(1 for v in sample if parse_date(v) is not None)
    if date_count > len(sample) * 0.8:  # 80% threshold
        return 'date'
    
    # Check if numeric
    numeric_count = 0
    for v in sample:
        try:
            float(v.strip())
            numeric_count += 1
        except ValueError:
            pass
    
    if numeric_count > len(sample) * 0.8:  # 80% threshold
        return 'numeric'
    
    return 'text'


def create_sort_key(value, column_type):
    """
    Create a sort key based on the column type.
    Handles None/empty values by pushing them to the end.
    """
    if not value or not value.strip():
        # Empty values sort to the end
        if column_type == 'numeric':
            return (1, float('inf'))
        elif column_type == 'date':
            return (1, datetime.max)
        else:
            return (1, '')
    
    try:
        if column_type == 'numeric':
            return (0, float(value.strip()))
        elif column_type == 'date':
            parsed = parse_date(value)
            if parsed:
                return (0, parsed)
            else:
                return (1, value.lower())  # Fall back to text sorting
        else:  # text
            return (0, value.lower())
    except (ValueError, AttributeError):
        # Fall back to text sorting
        return (0, str(value).lower())


def read_csv(filepath):
    """Read CSV file and return headers and rows."""
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        headers = next(reader)
        rows = list(reader)
    return headers, rows


def write_csv(filepath, headers, rows):
    """Write sorted data to CSV file."""
    with open(filepath, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Sort CSV files by one or more columns with intelligent data type handling',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Interactive mode
  python csv_sorter.py data.csv
  
  # Sort by column 2 (ascending)
  python csv_sorter.py data.csv -c 2
  
  # Sort by column 2 descending
  python csv_sorter.py data.csv -c 2 -d
  
  # Sort by column name
  python csv_sorter.py data.csv -c "Last Name"
  
  # Multi-column sort: first by column 2 (asc), then by column 5 (desc)
  python csv_sorter.py data.csv -c 2 -c 5:desc
  
  # Multi-column with mixed orders
  python csv_sorter.py data.csv -c "Department" -c "Salary:desc" -c "Name:asc"
  
  # Specify output file
  python csv_sorter.py data.csv -c 1 -o sorted.csv
        '''
    )
    
    parser.add_argument('input_file', nargs='?', help='Input CSV file path')
    parser.add_argument('-c', '--column', action='append', dest='columns',
                        help='Column to sort by (number or name). Can specify multiple times. '
                             'Format: COLUMN or COLUMN:ORDER where ORDER is "asc" or "desc". '
                             'Example: -c 2 -c "Name:desc"')
    parser.add_argument('-d', '--descending', action='store_true',
                        help='Sort in descending order (applies to all columns without explicit order)')
    parser.add_argument('-o', '--output', help='Output CSV file path (default: sorted_output.csv)')
    parser.add_argument('--show-columns', action='store_true',
                        help='Show available columns and exit')
    
    return parser.parse_args()


def parse_column_spec(spec, headers):
    """
    Parse a column specification which can be:
    - A number (1-indexed): "2"
    - A column name: "Last Name"
    - A number with order: "2:desc"
    - A column name with order: "Last Name:asc"
    
    Returns: (col_idx, reverse) or None if invalid
    """
    spec = spec.strip()
    
    # Check if order is specified
    if ':' in spec:
        col_part, order_part = spec.rsplit(':', 1)
        col_part = col_part.strip()
        order_part = order_part.strip().lower()
        
        if order_part in ['asc', 'ascending']:
            reverse = False
        elif order_part in ['desc', 'descending']:
            reverse = True
        else:
            print(f"Warning: Invalid sort order '{order_part}', using ascending")
            reverse = False
    else:
        col_part = spec
        reverse = None  # Will use default
    
    # Try to parse as number (1-indexed)
    try:
        col_num = int(col_part)
        col_idx = col_num - 1
        if 0 <= col_idx < len(headers):
            return (col_idx, reverse)
        else:
            print(f"Warning: Column number {col_num} out of range (1-{len(headers)})")
            return None
    except ValueError:
        # Try to find by name
        col_name = col_part.strip('"').strip("'")  # Remove quotes if present
        try:
            col_idx = headers.index(col_name)
            return (col_idx, reverse)
        except ValueError:
            # Try case-insensitive match
            for i, header in enumerate(headers):
                if header.lower() == col_name.lower():
                    return (i, reverse)
            print(f"Warning: Column '{col_name}' not found")
            return None


def get_column_choices(headers):
    """Prompt user to select columns for sorting."""
    print("\nAvailable columns:")
    for i, header in enumerate(headers, 1):
        print(f"  {i}. {header}")
    
    sort_columns = []
    
    print("\nYou can sort by multiple columns (primary, secondary, etc.)")
    print("Press Enter without a number when done.")
    
    while True:
        try:
            if sort_columns:
                prompt = f"\nEnter column number for sort priority {len(sort_columns) + 1} (or press Enter to finish): "
            else:
                prompt = "\nEnter column number for primary sort: "
            
            choice = input(prompt).strip()
            
            # Allow user to finish entering columns
            if not choice and sort_columns:
                break
            
            if not choice:
                print("Please enter at least one column")
                continue
            
            col_idx = int(choice) - 1
            if 0 <= col_idx < len(headers):
                if col_idx in [c[0] for c in sort_columns]:
                    print(f"Column '{headers[col_idx]}' already selected")
                    continue
                
                # Get sort order for this column
                while True:
                    order = input(f"Sort order for '{headers[col_idx]}' (a=ascending, d=descending): ").strip().lower()
                    if order in ['a', 'asc', 'ascending']:
                        reverse = False
                        break
                    elif order in ['d', 'desc', 'descending']:
                        reverse = True
                        break
                    else:
                        print("Please enter 'a' for ascending or 'd' for descending")
                
                sort_columns.append((col_idx, reverse))
                print(f"✓ Added '{headers[col_idx]}' ({'descending' if reverse else 'ascending'})")
            else:
                print(f"Please enter a number between 1 and {len(headers)}")
        except ValueError:
            print("Please enter a valid number")
    
    return sort_columns
    
    return sort_columns


def main():
    args = parse_arguments()
    
    # Get input file
    if args.input_file:
        input_file = args.input_file
    else:
        input_file = input("Enter CSV file path: ").strip()
    
    # Validate file exists
    if not Path(input_file).exists():
        print(f"Error: File '{input_file}' not found")
        sys.exit(1)
    
    # Read CSV
    print(f"\nReading '{input_file}'...")
    headers, rows = read_csv(input_file)
    print(f"Found {len(rows)} rows with {len(headers)} columns")
    
    if not rows:
        print("Error: CSV file is empty")
        sys.exit(1)
    
    # Show columns and exit if requested
    if args.show_columns:
        print("\nAvailable columns:")
        for i, header in enumerate(headers, 1):
            print(f"  {i}. {header}")
        sys.exit(0)
    
    # Get sorting parameters
    sort_columns = []
    
    if args.columns:
        # Use command-line arguments
        default_reverse = args.descending
        
        for col_spec in args.columns:
            result = parse_column_spec(col_spec, headers)
            if result:
                col_idx, reverse = result
                # If no explicit order specified, use default
                if reverse is None:
                    reverse = default_reverse
                
                # Check for duplicates
                if col_idx not in [c[0] for c in sort_columns]:
                    sort_columns.append((col_idx, reverse))
                    print(f"✓ Will sort by '{headers[col_idx]}' ({'descending' if reverse else 'ascending'})")
                else:
                    print(f"Warning: Ignoring duplicate column '{headers[col_idx]}'")
        
        if not sort_columns:
            print("Error: No valid columns specified")
            sys.exit(1)
    else:
        # Interactive mode
        sort_columns = get_column_choices(headers)
    
    # Detect column types for each sort column
    column_types = {}
    print("\nDetecting column types...")
    for col_idx, _ in sort_columns:
        column_values = [row[col_idx] if col_idx < len(row) else '' for row in rows]
        column_type = detect_column_type(column_values)
        column_types[col_idx] = column_type
        print(f"  {headers[col_idx]}: {column_type}")
    
    # Sort the rows by multiple columns
    print("\nSorting...")
    
    # Create a compound sort key function
    def multi_column_key(row):
        keys = []
        for col_idx, reverse in sort_columns:
            value = row[col_idx] if col_idx < len(row) else ''
            key = create_sort_key(value, column_types[col_idx])
            # If descending, we need to invert the key for proper multi-column sorting
            if reverse:
                # Invert the sort order by negating numbers, reversing dates, etc.
                if column_types[col_idx] == 'numeric':
                    keys.append((key[0], -key[1] if key[1] != float('inf') else key[1]))
                elif column_types[col_idx] == 'date':
                    # For dates, we'll use a tuple that sorts in reverse
                    if key[0] == 0:
                        # Convert datetime to negative timestamp for reverse sorting
                        keys.append((key[0], -key[1].timestamp()))
                    else:
                        keys.append(key)
                else:  # text
                    # For text, we'll reverse later by using reverse parameter per column
                    # This is handled differently - we'll use a wrapper
                    keys.append(key)
            else:
                keys.append(key)
        return keys
    
    # For mixed ascending/descending, we need a different approach
    # Sort by each column in reverse priority order
    sorted_rows = rows[:]
    for col_idx, reverse in reversed(sort_columns):
        sorted_rows = sorted(
            sorted_rows,
            key=lambda row: create_sort_key(row[col_idx] if col_idx < len(row) else '', column_types[col_idx]),
            reverse=reverse
        )
    
    # Get output file
    if args.output:
        output_file = args.output
    else:
        output_file = input("\nEnter output file path (press Enter for 'sorted_output.csv'): ").strip()
        if not output_file:
            output_file = 'sorted_output.csv'
    
    # Write output
    write_csv(output_file, headers, sorted_rows)
    print(f"\n✓ Sorted CSV saved to '{output_file}'")
    print(f"\nSort order applied:")
    for i, (col_idx, reverse) in enumerate(sort_columns, 1):
        print(f"  {i}. {headers[col_idx]} - {'Descending' if reverse else 'Ascending'} ({column_types[col_idx]})")



if __name__ == "__main__":
    main()
