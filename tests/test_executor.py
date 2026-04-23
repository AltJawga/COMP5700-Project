import unittest
import os
from executor import read_task2_txt_files

class TestExecutor(unittest.TestCase):
    def test_read_task2_txt_files(self):
        # Use dummy test files
        file1 = os.path.join('tests', 'dummy', 'dummy_doc1.txt')
        file2 = os.path.join('tests', 'dummy', 'dummy_requirements_differences.txt')
        content1, content2 = read_task2_txt_files(file1, file2)
        # Check that contents are non-empty strings
        self.assertIsInstance(content1, str)
        self.assertIsInstance(content2, str)
        self.assertGreater(len(content1), 0)
        self.assertGreater(len(content2), 0)


if __name__ == '__main__':
    unittest.main()
