import pandas as pd
import os
import glob

def combine_csv_files():
    """
    Scans folder for CSV files, lets user select files to combine,
    adds a Data Source column, and saves the combined file.
    """
    print("=== CSV File Combiner ===\n")
    
    # Scan current folder for CSV files
    csv_files_in_folder = glob.glob("*.csv")
    
    if len(csv_files_in_folder) == 0:
        print("No CSV files found in the current folder.")
        return
    
    if len(csv_files_in_folder) < 2:
        print("At least 2 CSV files are required to combine. Only 1 file found.")
        return
    
    # Display available CSV files
    print("Available CSV files in current folder:")
    print("-" * 40)
    for i, filename in enumerate(csv_files_in_folder, 1):
        print(f"  {i}. {filename}")
    print("-" * 40)
    
    # Ask user to select files
    print("\nSelect files to combine by entering their numbers separated by commas.")
    print("Example: 1,2,3 or 1,3,4")
    
    while True:
        selection = input("\nEnter your selection: ").strip()
        try:
            selected_indices = [int(x.strip()) for x in selection.split(",")]
            
            # Validate selection
            if len(selected_indices) < 2:
                print("  Please select at least 2 files.")
                continue
            
            if any(i < 1 or i > len(csv_files_in_folder) for i in selected_indices):
                print(f"  Invalid selection. Please enter numbers between 1 and {len(csv_files_in_folder)}.")
                continue
            
            # Check for duplicate selections
            if len(selected_indices) != len(set(selected_indices)):
                print("  Duplicate selections detected. Please select each file only once.")
                continue
            
            break
        except ValueError:
            print("  Invalid input. Please enter numbers separated by commas.")
    
    # Get selected file names
    selected_files = [csv_files_in_folder[i - 1] for i in selected_indices]
    
    print(f"\nYou selected {len(selected_files)} files:")
    for filename in selected_files:
        print(f"  - {filename}")
    
    # Ask for Data Source value for each file
    print("\n" + "=" * 40)
    print("DATA SOURCE VALUES")
    print("=" * 40)
    print("Enter a 'Data Source' value for each file.")
    print("This value will be added as a new column to identify rows from each file.\n")
    
    data_sources = {}
    for filename in selected_files:
        data_source = input(f"  Data Source for '{filename}': ").strip()
        data_sources[filename] = data_source
    
    # Get output file name
    output_filename = input("\nEnter the name for the output CSV file: ").strip()
    if not output_filename.endswith('.csv'):
        output_filename += '.csv'
    
    # Check if output file already exists
    if os.path.exists(output_filename):
        while True:
            response = input(f"\nFile '{output_filename}' already exists. Replace it? (yes/no): ").strip().lower()
            if response in ['yes', 'y']:
                print(f"  File will be replaced.")
                break
            elif response in ['no', 'n']:
                print("  Operation cancelled.")
                return
            else:
                print("  Please enter 'yes' or 'no'.")
    
    # Read and combine CSV files
    print("\nReading CSV files...")
    dataframes = []
    row_counts = []
    column_info = {}  # Store column info for each file
    
    for filename in selected_files:
        try:
            df = pd.read_csv(filename)
            dataframes.append(df)
            row_counts.append(len(df))
            column_info[filename] = list(df.columns)
            print(f"  ✓ Successfully read '{filename}'")
        except FileNotFoundError:
            print(f"  ✗ Error: File '{filename}' not found.")
            return
        except Exception as e:
            print(f"  ✗ Error reading '{filename}': {e}")
            return
    
    # Validate that all files have the same columns in the same order
    print("\nValidating column structure...")
    reference_file = selected_files[0]
    reference_columns = column_info[reference_file]
    column_errors = []
    
    for filename in selected_files[1:]:
        current_columns = column_info[filename]
        
        # Check if column counts match
        if len(current_columns) != len(reference_columns):
            column_errors.append({
                'file': filename,
                'issue': 'Column count mismatch',
                'details': f"Expected {len(reference_columns)} columns, found {len(current_columns)} columns"
            })
            continue
        
        # Check each column name and order
        for i, (ref_col, curr_col) in enumerate(zip(reference_columns, current_columns)):
            if ref_col != curr_col:
                column_errors.append({
                    'file': filename,
                    'issue': 'Column name/order mismatch',
                    'details': f"Position {i + 1}: Expected '{ref_col}', found '{curr_col}'"
                })
    
    # If there are column errors, display them and stop processing
    if column_errors:
        print("\n" + "=" * 50)
        print("❌ COLUMN VALIDATION FAILED")
        print("=" * 50)
        print(f"\nReference file: '{reference_file}'")
        print(f"Reference columns ({len(reference_columns)}):")
        for i, col in enumerate(reference_columns, 1):
            print(f"  {i}. {col}")
        
        print("\n" + "-" * 50)
        print("ERRORS FOUND:")
        print("-" * 50)
        
        for error in column_errors:
            print(f"\n  File: '{error['file']}'")
            print(f"  Issue: {error['issue']}")
            print(f"  Details: {error['details']}")
            
            # Show the columns of the mismatched file
            mismatched_columns = column_info[error['file']]
            print(f"  Columns in this file ({len(mismatched_columns)}):")
            for i, col in enumerate(mismatched_columns, 1):
                marker = ""
                if i <= len(reference_columns) and col != reference_columns[i - 1]:
                    marker = " ← DIFFERENT"
                elif i > len(reference_columns):
                    marker = " ← EXTRA"
                print(f"    {i}. {col}{marker}")
            
            # Show missing columns if any
            if len(mismatched_columns) < len(reference_columns):
                print(f"  Missing columns:")
                for i in range(len(mismatched_columns), len(reference_columns)):
                    print(f"    {i + 1}. {reference_columns[i]} ← MISSING")
        
        print("\n" + "=" * 50)
        print("Please correct the column structure in the files")
        print("listed above before combining.")
        print("=" * 50)
        return
    
    print("  ✓ All files have matching column structure")
    
    # Add Data Source column to each dataframe as the first column
    for i, filename in enumerate(selected_files):
        dataframes[i].insert(0, 'Data Source', data_sources[filename])
    
    # Combine all dataframes
    combined_df = pd.concat(dataframes, ignore_index=True)
    
    # Display statistics
    print("\n" + "=" * 40)
    print("FILE STATISTICS")
    print("=" * 40)
    for i, (filename, count) in enumerate(zip(selected_files, row_counts), 1):
        print(f"  File {i} ({filename}): {count:,} rows")
        print(f"          Data Source: '{data_sources[filename]}'")
    print("-" * 40)
    print(f"  Combined file: {len(combined_df):,} rows")
    print("=" * 40)
    
    # Check for duplicates based on first column (after Data Source)
    first_data_column = combined_df.columns[1]  # Skip Data Source column
    duplicate_count = combined_df.duplicated(subset=[first_data_column], keep='first').sum()
    
    if duplicate_count > 0:
        print(f"\n⚠ Found {duplicate_count:,} duplicate(s) based on column '{first_data_column}'")
        while True:
            response = input("  Do you want to remove duplicates? (yes/no): ").strip().lower()
            if response in ['yes', 'y']:
                combined_df = combined_df.drop_duplicates(subset=[first_data_column], keep='first')
                print(f"  ✓ Duplicates removed. New row count: {len(combined_df):,}")
                break
            elif response in ['no', 'n']:
                print("  Duplicates will be kept.")
                break
            else:
                print("  Please enter 'yes' or 'no'.")
    else:
        print(f"\n✓ No duplicates found based on column '{first_data_column}'")
    
    # Show columns and give option to delete
    print("\n" + "=" * 40)
    print("COLUMNS IN COMBINED FILE")
    print("=" * 40)
    columns_list = list(combined_df.columns)
    for i, col in enumerate(columns_list, 1):
        print(f"  {i}. {col}")
    print("=" * 40)
    
    while True:
        response = input("\nDo you want to delete any columns? (yes/no): ").strip().lower()
        if response in ['yes', 'y']:
            print("\nEnter column numbers to delete, separated by commas.")
            print("Example: 3,5,7")
            
            while True:
                selection = input("\nColumns to delete (or 'done' to finish): ").strip().lower()
                
                if selection == 'done':
                    break
                
                try:
                    selected_indices = [int(x.strip()) for x in selection.split(",")]
                    
                    # Validate selection
                    invalid_indices = [i for i in selected_indices if i < 1 or i > len(columns_list)]
                    if invalid_indices:
                        print(f"  Invalid column number(s): {invalid_indices}. Please enter numbers between 1 and {len(columns_list)}.")
                        continue
                    
                    # Get column names to delete
                    columns_to_delete = [columns_list[i - 1] for i in selected_indices]
                    
                    # Confirm deletion
                    print(f"\n  Columns to be deleted:")
                    for col in columns_to_delete:
                        print(f"    - {col}")
                    
                    confirm = input("\n  Confirm deletion? (yes/no): ").strip().lower()
                    if confirm in ['yes', 'y']:
                        combined_df = combined_df.drop(columns=columns_to_delete)
                        columns_list = list(combined_df.columns)
                        print(f"  ✓ Deleted {len(columns_to_delete)} column(s)")
                        
                        # Show updated columns
                        print("\n  Updated columns:")
                        for i, col in enumerate(columns_list, 1):
                            print(f"    {i}. {col}")
                        
                        # Ask if user wants to delete more
                        more = input("\n  Delete more columns? (yes/no): ").strip().lower()
                        if more not in ['yes', 'y']:
                            break
                    else:
                        print("  Deletion cancelled.")
                        
                except ValueError:
                    print("  Invalid input. Please enter numbers separated by commas.")
            break
        elif response in ['no', 'n']:
            print("  No columns will be deleted.")
            break
        else:
            print("  Please enter 'yes' or 'no'.")
    
    # Save to CSV
    print(f"\nSaving to '{output_filename}'...")
    while True:
        try:
            combined_df.to_csv(output_filename, index=False)
            print(f"  ✓ Successfully saved to '{output_filename}'")
            break
        except PermissionError:
            print(f"  ✗ Permission denied: '{output_filename}'")
            print(f"    The file may be open in another program (e.g., Excel).")
            response = input("    Close the file and try again? (yes/no): ").strip().lower()
            if response in ['yes', 'y']:
                continue
            else:
                print("  Operation cancelled.")
                return
        except Exception as e:
            print(f"  ✗ Error saving file: {e}")
            return
    
    print("\nDone!")

if __name__ == "__main__":
    combine_csv_files()
