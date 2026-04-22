"""
comparator.py - Task 2: Comparator

Compares two YAML files produced by Task-1 (extractor.py) and reports:
  1. Differences in KDE *names*           → name_differences.txt
  2. Differences in KDE names AND reqs    → requirement_differences.txt
"""

import os
import sys
import glob
import yaml


# ---------------------------------------------------------------------------
# Function 1 – Load the two YAML files produced by Task-1
# ---------------------------------------------------------------------------

def load_yaml_files(yaml_path1: str = None, yaml_path2: str = None):
    """
    Automatically locate and load the two YAML files produced by Task-1.

    If explicit paths are supplied they are used directly; otherwise the
    function searches the current working directory for files matching the
    pattern '*-kdes.yaml' (the naming convention used by extractor.py).

    Returns
    -------
    tuple[dict, str, dict, str]
        (data1, filename1, data2, filename2)

    Raises
    ------
    FileNotFoundError  – if a supplied path does not exist.
    ValueError         – if auto-discovery finds != 2 YAML files.
    yaml.YAMLError     – if a file cannot be parsed.
    """

    def _load(path: str) -> dict:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"YAML file not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise ValueError(
                f"Expected a YAML mapping at the top level in '{path}', "
                f"got {type(data).__name__}."
            )
        return data

    # --- Auto-discovery -------------------------------------------------------
    if yaml_path1 is None or yaml_path2 is None:
        candidates = sorted(glob.glob("*-kdes.yaml"))
        if len(candidates) != 2:
            raise ValueError(
                f"Auto-discovery expected exactly 2 '*-kdes.yaml' files in "
                f"the current directory, found {len(candidates)}: {candidates}. "
                f"Pass explicit paths to load_yaml_files() to override."
            )
        yaml_path1, yaml_path2 = candidates[0], candidates[1]

    data1 = _load(yaml_path1)
    data2 = _load(yaml_path2)

    print(f"[load_yaml_files] Loaded '{yaml_path1}' ({len(data1)} KDEs) "
          f"and '{yaml_path2}' ({len(data2)} KDEs).")

    return data1, yaml_path1, data2, yaml_path2


# ---------------------------------------------------------------------------
# Helper – normalise a single KDE entry into a flat set of requirement strings
# ---------------------------------------------------------------------------

def _get_requirements(kde_value) -> set:
    """
    Extract requirements from a KDE dict value produced by extractor.py.

    Handles the nested structure:
        element1:
          name: ...
          requirements:
            - req1
            - req2
    as well as simpler flat structures.
    """
    if kde_value is None:
        return set()

    reqs = set()

    if isinstance(kde_value, dict):
        raw = kde_value.get("requirements", [])
        if isinstance(raw, list):
            reqs = {str(r).strip() for r in raw if r}
        elif isinstance(raw, str):
            reqs = {raw.strip()} if raw.strip() else set()
        elif isinstance(raw, dict):
            reqs = {str(v).strip() for v in raw.values() if v}

    elif isinstance(kde_value, list):
        reqs = {str(r).strip() for r in kde_value if r}

    elif isinstance(kde_value, str):
        reqs = {kde_value.strip()} if kde_value.strip() else set()

    return reqs


# ---------------------------------------------------------------------------
# Helper – canonical KDE name from a value dict (falls back to the key)
# ---------------------------------------------------------------------------

def _get_name(key: str, kde_value) -> str:
    if isinstance(kde_value, dict):
        return str(kde_value.get("name", key)).strip()
    return key


# ---------------------------------------------------------------------------
# Function 2 – Compare KDE *names* only
# ---------------------------------------------------------------------------

def compare_kde_names(
    data1: dict,
    filename1: str,
    data2: dict,
    filename2: str,
    output_path: str = "name_differences.txt",
) -> str:
    """
    Compare the two YAML datasets on KDE *names* only.

    A KDE is identified by the 'name' field inside its entry (or the top-level
    key when no 'name' field exists).  The comparison is case-insensitive.

    Output
    ------
    Writes ``output_path`` and returns its path.
    """

    # Build name → original-key maps (lowercase name as canonical id)
    def name_map(data: dict) -> dict:
        """Returns {lower_name: display_name}"""
        result = {}
        for key, val in data.items():
            display = _get_name(key, val)
            result[display.lower()] = display
        return result
    
    def merge_sections(data: dict) -> dict:
        merged = {}
        """Merge all KDE sections into a single dict for easier processing."""
        for section in ['zero_shot_kdes', 'few_shot_kdes', 'chain_of_thought_kdes']:
            if section in data and isinstance(data[section], dict):
                merged.update(data[section])
        return merged
    
    merged1 = merge_sections(data1)
    merged2 = merge_sections(data2)

    names1 = name_map(merged1)   # {lower: display}  from file1
    names2 = name_map(merged2)   # {lower: display}  from file2

    only_in_1 = {n: names1[n] for n in names1 if n not in names2}
    only_in_2 = {n: names2[n] for n in names2 if n not in names1}

    base1 = os.path.basename(filename1)
    base2 = os.path.basename(filename2)

    lines = []

    if not only_in_1 and not only_in_2:
        lines.append("NO DIFFERENCES IN REGARDS TO ELEMENT NAMES")
    else:
        lines.append(f"KDE NAME DIFFERENCES BETWEEN '{base1}' AND '{base2}'")
        lines.append("=" * 70)

        if only_in_1:
            lines.append(f"\nPresent in '{base1}' but ABSENT in '{base2}':")
            for display in sorted(only_in_1.values()):
                lines.append(f"  - {display}")

        if only_in_2:
            lines.append(f"\nPresent in '{base2}' but ABSENT in '{base1}':")
            for display in sorted(only_in_2.values()):
                lines.append(f"  - {display}")

    content = "\n".join(lines) + "\n"
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)

    print(f"[compare_kde_names] Written → '{output_path}'")
    return output_path


# ---------------------------------------------------------------------------
# Function 3 – Compare KDE names AND their requirements
# ---------------------------------------------------------------------------

def compare_kde_requirements(
    data1: dict,
    filename1: str,
    data2: dict,
    filename2: str,
    output_path: str = "requirement_differences.txt",
) -> str:
    """
    Compare the two YAML datasets on both KDE *names* and *requirements*.

    Output format (one tuple per line):
        NAME,ABSENT-IN-<FILE>,PRESENT-IN-<FILE>,NA
        NAME,ABSENT-IN-<FILE>,PRESENT-IN-<FILE>,<REQ>

    * NA  – the KDE itself is absent in one file.
    * REQ – a specific requirement present in one file but not the other.

    Writes ``output_path`` and returns its path.
    """

    base1 = os.path.basename(filename1)
    base2 = os.path.basename(filename2)

    # Build {lower_name: (display_name, req_set)} for each file
    def kde_map(data: dict) -> dict:
        result = {}
        for key, val in data.items():
            display = _get_name(key, val)
            reqs = _get_requirements(val)
            result[display.lower()] = (display, reqs)
        return result
    
    def merge_sections(data: dict) -> dict:
        merged = {}
        """Merge all KDE sections into a single dict for easier processing."""
        for section in ['zero_shot_kdes', 'few_shot_kdes', 'chain_of_thought_kdes']:
            if section in data and isinstance(data[section], dict):
                merged.update(data[section])
        return merged

    merged1 = merge_sections(data1)
    merged2 = merge_sections(data2)
    
    map1 = kde_map(merged1)
    map2 = kde_map(merged2)

    all_names = sorted(set(map1) | set(map2))

    tuples = []

    for lower_name in all_names:
        in1 = lower_name in map1
        in2 = lower_name in map2

        # Prefer the display name from whichever file has it (or both)
        display = (map1[lower_name][0] if in1 else map2[lower_name][0])

        if in1 and not in2:
            # Entirely absent from file2
            tuples.append(f"{display},ABSENT-IN-{base2},PRESENT-IN-{base1},NA")

        elif in2 and not in1:
            # Entirely absent from file1
            tuples.append(f"{display},ABSENT-IN-{base1},PRESENT-IN-{base2},NA")

        else:
            # Present in both – compare requirements
            reqs1 = map1[lower_name][1]
            reqs2 = map2[lower_name][1]

            only_req_in_1 = reqs1 - reqs2
            only_req_in_2 = reqs2 - reqs1

            for req in sorted(only_req_in_1):
                tuples.append(
                    f"{display},ABSENT-IN-{base2},PRESENT-IN-{base1},{req}"
                )
            for req in sorted(only_req_in_2):
                tuples.append(
                    f"{display},ABSENT-IN-{base1},PRESENT-IN-{base2},{req}"
                )

    if not tuples:
        content = "NO DIFFERENCES IN REGARDS TO ELEMENT REQUIREMENTS\n"
    else:
        header = (
            f"# Requirement differences between '{base1}' and '{base2}'\n"
            f"# Format: NAME,ABSENT-IN-<FILE>,PRESENT-IN-<FILE>,REQ_OR_NA\n"
        )
        content = header + "\n".join(tuples) + "\n"

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)

    print(f"[compare_kde_requirements] Written → '{output_path}'")
    return output_path


# ---------------------------------------------------------------------------
# Main – wire everything together
# ---------------------------------------------------------------------------

def main(yaml_path1: str = None, yaml_path2: str = None):
    """
    Run the full Task-2 pipeline.

    Parameters
    ----------
    yaml_path1, yaml_path2 : str, optional
        Explicit paths to the two YAML files.  When omitted the script
        auto-discovers '*-kdes.yaml' files in the current directory.
    """
    # Step 1 – load
    data1, fname1, data2, fname2 = load_yaml_files(yaml_path1, yaml_path2)

    # Step 2 – name differences
    compare_kde_names(data1, fname1, data2, fname2,
                      output_path="name_differences.txt")

    # Step 3 – name + requirement differences
    compare_kde_requirements(data1, fname1, data2, fname2,
                             output_path="requirement_differences.txt")

    print("\n[main] Task-2 complete.  Output files:")
    print("  • name_differences.txt")
    print("  • requirement_differences.txt")


if __name__ == "__main__":
    # Hardcode your file paths here for Google Colab
    file1_path = "cis-r1-kdes.yaml"
    file2_path = "cis-r2-kdes.yaml"
    
    # Run the main function with the hardcoded paths
    main(file1_path, file2_path)