def read_task2_txt_files(file1_path, file2_path):
    """
    Reads and returns the contents of two Task-2 TXT files.
    Args:
        file1_path (str): Path to the first TXT file.
        file2_path (str): Path to the second TXT file.
    Returns:
        tuple: (content1, content2) as strings.
    """
    with open(file1_path, 'r', encoding='utf-8') as f1:
        content1 = f1.read()
    with open(file2_path, 'r', encoding='utf-8') as f2:
        content2 = f2.read()
    return content1, content2

if __name__ == "__main__":
    # Example usage:
    file1 = 'name_differences.txt'
    file2 = 'requirement_differences.txt'
    content1, content2 = read_task2_txt_files(file1, file2)
    print("Content of File 1:")
    print(content1)
    print("\nContent of File 2:")
    print(content2)
