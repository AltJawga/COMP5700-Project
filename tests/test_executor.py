import unittest
import os
from executor import read_task2_txt_files, analyze_and_map_differences
from executor import map_difference_to_kubescape_control, CONTROL_PATTERNS
import pandas as pd
from executor import run_kubescape, export_df_to_csv

class TestExecutor(unittest.TestCase):
    def setUp(self):
        print("setting up executor testbed")
        # Setup can include creating dummy files or data if needed
        self.dummy_name_diff = os.path.abspath(os.path.join(os.path.dirname(__file__), 'dummy', 'dummy_name_differences.txt'))
        self.dummy_req_diff = os.path.abspath(os.path.join(os.path.dirname(__file__), 'dummy', 'dummy_requirements_differences.txt'))
        self.contentOne, self.contentTwo = read_task2_txt_files(self.dummy_name_diff, self.dummy_req_diff)

    def test_read_task2_txt_files(self):
        print("testing reading task2 txt files")
        # Use dummy test files
        file1 = self.dummy_name_diff
        file2 = self.dummy_req_diff
        content1, content2 = read_task2_txt_files(file1, file2)
        # Check that contents are non-empty strings
        self.assertIsInstance(content1, str)
        self.assertIsInstance(content2, str)
        self.assertGreater(len(content1), 0)
        self.assertGreater(len(content2), 0)

    def test_difference_to_cid_mapping(self):
        print("testing difference to CID mapping")
        # This test would require a sample mapping file and expected output
        # For now, we can just check that the function runs without error
        mapping = analyze_and_map_differences(self.contentOne, self.contentTwo)
        self.assertIn("C-0035", mapping)  # Example CID that should be in the mapping based on dummy data
        self.assertIn("C-0053", mapping)
        self.assertIn("C-0222", mapping)

        empty_mapping = analyze_and_map_differences("", "")
        self.assertIn("NO DIFFERENCES FOUND", empty_mapping)
        if os.path.exists("kubescape_controls.txt"):
            os.remove("kubescape_controls.txt")


    def test_run_kubescape(self):
        print("testing run kubescape")
        # This test assumes a small dummy scan or a mock of run_kubescape
        # Use a dummy control and dummy input path (should be replaced with a real or mock call in CI)
        controls = ["C-0035"]
        input_path = "project-yamls"  # Should exist or be mocked
        try:
            output = run_kubescape(controls, input_path)
            assert(output)
            self.assertIn("summaryDetails", output)  # Basic check for expected output structure
            self.assertIn("Administrative Roles", output)
        except Exception as e:
            self.fail(f"run_kubescape or DataFrame creation failed: {e}")

    def test_export_df_to_csv(self):
        print("test df to csv export")
        # Create a dummy DataFrame
        df = pd.DataFrame([
            {"FilePath": "dummy.yaml", "Severity": "Medium", "Control name": "Test Control", "Failed resources": 2, "All Resources": 10, "Compliance score": 80.0}
        ])
        try:
            export_df_to_csv(df, "test_kubescape_results.csv")
            self.assertTrue(os.path.exists("test_kubescape_results.csv"))
            # Optionally, check contents
            with open("test_kubescape_results.csv", "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("FilePath", content)
                self.assertIn("Test Control", content)
        finally:
            if os.path.exists("test_kubescape_results.csv"):
                os.remove("test_kubescape_results.csv")
 

if __name__ == '__main__':
    unittest.main()
