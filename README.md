# CSV Toolkit

A pair of Python scripts for combining and sorting CSV files.

---

## Scripts

### 1. `combine_csv_files.py` — CSV File Combiner

Scans the current folder for CSV files, lets you select which ones to combine, and merges them into a single output file.

**Requirements:** `pandas`

```bash
pip install pandas
python combine_csv_files.py
```

**Interactive workflow:**

1. The script lists all `.csv` files in the current directory.
2. You select which files to combine (minimum 2) by entering their numbers separated by commas.
3. You assign a **Data Source** label to each file — this is added as the first column in the output so every row is traceable to its origin file.
4. You name the output file.
5. The script validates that all selected files share identical column names and order. If any mismatch is found, it reports the exact differences and stops.
6. It checks for duplicate rows based on the first data column and gives you the option to remove them.
7. You can optionally delete columns from the combined dataset before saving.

**Key behaviours:**

- Requires all input files to have the same columns in the same order.
- The `Data Source` column is inserted as the first column in the output.
- Duplicate detection is based on the first non-`Data Source` column only.
- Prompts before overwriting an existing output file.
- Handles `PermissionError` gracefully if the output file is open in another program (e.g. Excel).

---

### 2. `csv_sorter.py` — CSV Sorter

Sorts a CSV file by one or more columns, with automatic detection of numeric, date, and text column types.

**Requirements:** Python standard library only (no additional packages needed)

```bash
python csv_sorter.py [input_file] [options]
```

**Usage examples:**

```bash
# Interactive mode — prompts for file path and column choices
python csv_sorter.py

# Sort by column 2, ascending (default)
python csv_sorter.py data.csv -c 2

# Sort by column 2, descending
python csv_sorter.py data.csv -c 2 -d

# Sort by column name
python csv_sorter.py data.csv -c "Last Name"

# Multi-column sort: column 2 ascending, then column 5 descending
python csv_sorter.py data.csv -c 2 -c 5:desc

# Sort by column name with mixed orders
python csv_sorter.py data.csv -c "Department" -c "Salary:desc" -c "Name:asc"

# Specify output file
python csv_sorter.py data.csv -c 1 -o sorted.csv

# Show available columns and exit
python csv_sorter.py data.csv --show-columns
```

**Options:**

| Flag | Description |
|------|-------------|
| `-c`, `--column` | Column to sort by (number or name). Repeatable for multi-column sorting. Append `:asc` or `:desc` to set per-column order. |
| `-d`, `--descending` | Sort all columns (without an explicit order) in descending order. |
| `-o`, `--output` | Output file path. Defaults to `sorted_output.csv`. |
| `--show-columns` | Print available column names and exit. |

**Column type detection:**

The script samples up to 100 values per column and classifies it as one of three types, which determines how values are compared during sorting:

- **date** — recognises a wide range of formats including `March 16th 2025, 23:44:35`, ISO 8601, and common `MM/DD/YYYY` variants.
- **numeric** — standard integer and float values.
- **text** — case-insensitive alphabetical sort; empty values are sorted to the end.

**Multi-column sorting** is applied from lowest to highest priority (last column first), so the primary sort column takes precedence.

---

## Requirements

| Script | Dependencies |
|--------|-------------|
| `combine_csv_files.py` | `pandas` |
| `csv_sorter.py` | Python 3.6+ standard library only |
