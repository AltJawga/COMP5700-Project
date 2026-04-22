import os
import unittest
from unittest.mock import MagicMock, patch
from extractor import (
    load_and_validate_pdfs,
    generate_zero_shot_chunk_prompt,
    generate_few_shot_chunk_prompt,
    generate_chain_of_thought_chunk_prompt,
    extract_and_save_kdes_for_document,
    collect_and_dump_llm_outputs
)


class TestExtractorInputValidation(unittest.TestCase):
    def setUp(self):
        self.doc1 = os.path.join(os.path.dirname(__file__), 'dummy', 'dummy_doc1.pdf')
        self.doc2 = os.path.join(os.path.dirname(__file__), 'dummy', 'dummy_doc2.pdf')

    def test_load_and_validate_pdfs_file_not_found(self):
        print("Testing with non-existent files...")
        with self.assertRaises(FileNotFoundError):
            load_and_validate_pdfs('nonexistent1.pdf', 'nonexistent2.pdf')

    def test_load_and_validate_pdfs_wrong_type(self):
        print("Testing with wrong input types...")
        with self.assertRaises(TypeError):
            load_and_validate_pdfs(123, self.doc2)

    def test_load_and_validate_pdfs_wrong_extension(self):
        print("Testing with wrong file extensions...")
        with self.assertRaises(ValueError):
            load_and_validate_pdfs(self.doc1.replace('.pdf', '.txt'), self.doc2)


class TestPromptGeneration(unittest.TestCase):
    def test_generate_zero_shot_chunk_prompt(self):
        print("Testing zero-shot prompt generation...")
        filename = "dummy_doc1.pdf"
        text_chunk = "This is a test chunk."
        tables_string = "No tabular data found."
        prompt = generate_zero_shot_chunk_prompt(filename, text_chunk, tables_string)
        self.assertIn("You are an expert Cybersecurity Requirements Analyst", prompt)
        self.assertIn(filename, prompt)
        self.assertIn(text_chunk, prompt)
        self.assertIn(tables_string, prompt)
        self.assertIn("Output ONLY a valid YAML block", prompt)
        self.assertIn("element1:", prompt)
        self.assertIn("requirements:", prompt)

    def test_generate_few_shot_chunk_prompt(self):
        print("Testing few-shot prompt generation...")
        filename = "dummy_doc2.pdf"
        text_chunk = "Another test chunk."
        tables_string = "No tabular data found."
        prompt = generate_few_shot_chunk_prompt(filename, text_chunk, tables_string)
        self.assertIn("You are an expert Cybersecurity Requirements Analyst", prompt)
        self.assertIn(filename, prompt)
        self.assertIn(text_chunk, prompt)
        self.assertIn(tables_string, prompt)
        self.assertIn("--- EXAMPLE ---", prompt)
        self.assertIn("element1:", prompt)
        self.assertIn("requirements:", prompt)

    def test_generate_chain_of_thought_chunk_prompt(self):
        print("Testing chain-of-thought prompt generation...")
        filename = "dummy_doc1.pdf"
        text_chunk = "Chain of thought chunk."
        tables_string = "No tabular data found."
        prompt = generate_chain_of_thought_chunk_prompt(filename, text_chunk, tables_string)
        self.assertIn("You are an expert Cybersecurity Requirements Analyst", prompt)
        self.assertIn(filename, prompt)
        self.assertIn(text_chunk, prompt)
        self.assertIn(tables_string, prompt)
        self.assertIn("step-by-step reasoning", prompt)
        self.assertIn("FINAL YAML OUTPUT", prompt)
        self.assertIn("element1:", prompt)
        self.assertIn("requirements:", prompt)


class TestKDEExtraction(unittest.TestCase):

    def setUp(self):
        self.doc1 = os.path.join(os.path.dirname(__file__), 'dummy', 'dummy_doc1.pdf')
        self.doc2 = os.path.join(os.path.dirname(__file__), 'dummy', 'dummy_doc2.pdf')

    @patch('extractor.run_prompt_on_chunk')
    @patch('extractor.yaml.dump')
    @patch('extractor.open')
    def test_extract_and_save_kdes_for_document(self, mock_open, mock_yaml_dump, mock_run_prompt):
        # Mock output for each prompt type
        print("Testing KDE extraction and saving with mocking...")
        mock_kde_dict = {
            'element1': {
                'name': 'Encryption',
                'requirements': ['Data at rest must be encrypted using AES-256.']
            }
        }
        mock_record = {
            'llm_name': 'gemma-3-1b',
            'prompt_used': 'mock prompt',
            'prompt_type': 'zero_shot_chunk_1',
            'llm_output': 'mock llm output'
        }
        mock_run_prompt.return_value = (mock_kde_dict, mock_record)

        pdf_data = {
            self.doc1: {
                'text': 'Data at rest must be encrypted using AES-256.',
                'tables': []
            }
        }
        model = MagicMock()
        tokenizer = MagicMock()
        model_id = 'gemma-3-1b'

        records = extract_and_save_kdes_for_document(
            self.doc1, pdf_data, model, tokenizer, model_id, output_dir=os.path.dirname(__file__)
        )
        # Assert YAML dump was called (file writing suppressed)
        mock_yaml_dump.assert_called()
        # Assert the returned records contain the mocked record
        self.assertTrue(any(r['llm_name'] == 'gemma-3-1b' for r in records))


class TestLLMOutputDump(unittest.TestCase):
    def test_collect_and_dump_llm_outputs(self):
        print("Testing collection and dumping of LLM outputs...")
        # Create dummy LLM records
        llm_records = [
            {
                'llm_name': 'gemma-3-1b',
                'prompt_used': 'Prompt text here',
                'prompt_type': 'zero_shot',
                'llm_output': 'YAML output here'
            },
            {
                'llm_name': 'gemma-3-1b',
                'prompt_used': 'Another prompt',
                'prompt_type': 'few_shot',
                'llm_output': 'Another YAML output'
            }
        ]
        output_file = 'test_llm_outputs.txt'
        try:
            from extractor import collect_and_dump_llm_outputs
            collect_and_dump_llm_outputs(llm_records, output_filename=output_file)
            # Read the file and check for expected content
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.assertIn('*LLM Name*', content)
                self.assertIn('gemma-3-1b', content)
                self.assertIn('*Prompt Used*', content)
                self.assertIn('Prompt text here', content)
                self.assertIn('*Prompt Type*', content)
                self.assertIn('zero_shot', content)
                self.assertIn('*LLM Output*', content)
                self.assertIn('YAML output here', content)
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
