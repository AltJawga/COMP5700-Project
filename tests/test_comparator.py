import os
import unittest
from comparator import load_yaml_files, compare_kde_names, compare_kde_requirements

class TestComparator(unittest.TestCase):
    def setUp(self):
        # Use the dummy YAMLs in tests/dummy for isolated tests
        self.yaml1 = os.path.abspath(os.path.join(os.path.dirname(__file__), 'dummy', 'dummy-cis-r1-kdes.yaml'))
        self.yaml2 = os.path.abspath(os.path.join(os.path.dirname(__file__), 'dummy', 'dummy-cis-r2-kdes.yaml'))
        self.data1, self.fname1, self.data2, self.fname2 = load_yaml_files(self.yaml1, self.yaml2)

    def test_load_yaml_files(self):
        print("Testing YAML file loading and validation...")
        self.assertIsInstance(self.data1, dict)
        self.assertIsInstance(self.data2, dict)
        self.assertTrue(self.fname1.endswith('dummy-cis-r1-kdes.yaml'))
        self.assertTrue(self.fname2.endswith('dummy-cis-r2-kdes.yaml'))

    def test_compare_kde_names(self):

        output_path = 'test_name_differences.txt'
        print("Testing KDE name comparison and output...")
        try:
            result_file = compare_kde_names(self.data1, self.fname1, self.data2, self.fname2, output_path=output_path)
            self.assertTrue(os.path.isfile(result_file))
            with open(result_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.assertIn('KDE' or 'NO DIFFERENCES', content.upper())  # Should mention element names or no differences
                self.assertIn('Worker Node Configuration', content)  # Should mention the differing element name
                self.assertIn('Minimize User Access to Amazon ECR', content)  # Should mention the differing element name
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)

    def test_compare_kde_requirements(self):
        output_path = 'test_requirement_differences.txt'
        print("Testing KDE requirement comparison and output...")
        try:
            result_file = compare_kde_requirements(self.data1, self.fname1, self.data2, self.fname2, output_path=output_path)
            self.assertTrue(os.path.isfile(result_file))
            with open(result_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.assertIn('Authentication,ABSENT-IN-dummy-cis-r2-kdes.yaml,PRESENT-IN-dummy-cis-r1-kdes.yaml,User authentication will be handled via OAuth 2.0.', content)  # Should mention the differing requirement
                self.assertIn('Implement and Manage a Firewall on Servers,ABSENT-IN-dummy-cis-r1-kdes.yaml,PRESENT-IN-dummy-cis-r2-kdes.yaml,NA', content)  # Should mention the differing requirement
        finally:
            if os.path.exists(output_path):
                print("yeay")
                os.remove(output_path)

if __name__ == '__main__':
    unittest.main()
