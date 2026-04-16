import os
import re
import yaml
import torch
import pdfplumber
from transformers import AutoTokenizer, AutoModelForCausalLM
from google.colab import userdata

# ---------------------------------------------------------------------------
# Task 1a – Input validation, text extraction, and chunking
# ---------------------------------------------------------------------------

def load_and_validate_pdfs(doc1_path, doc2_path):
    documents = [doc1_path, doc2_path]
    extracted_data = {}

    for doc_path in documents:
        if not isinstance(doc_path, str):
            raise TypeError(f"Invalid input type: {doc_path}. Path must be a string.")
        if not os.path.isfile(doc_path):
            raise FileNotFoundError(f"File not found: {doc_path}")
        if not doc_path.lower().endswith('.pdf'):
            raise ValueError(f"Invalid file format: {doc_path}. File must be a PDF.")

        extracted_data[doc_path] = {
            "text": "",
            "tables": []
        }

        try:
            with pdfplumber.open(doc_path) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        extracted_data[doc_path]["text"] += page_text + "\n"
                    page_tables = page.extract_tables()
                    if page_tables:
                        extracted_data[doc_path]["tables"].extend(page_tables)
        except Exception as e:
            raise IOError(f"Failed to open or process the PDF '{doc_path}'. Error: {e}")

    return extracted_data

def format_tables_to_string(tables):
    if not tables:
        return "No tabular data found."

    table_strings = []
    for i, table in enumerate(tables):
        table_strings.append(f"--- Table {i+1} ---")
        for row in table:
            cleaned_row = [
                str(cell).replace('\n', ' ') if cell is not None else ""
                for cell in row
            ]
            table_strings.append(" | ".join(cleaned_row))
    return "\n".join(table_strings)

def chunk_content(text, words_per_chunk=3000):
    if not text:
        return [""]
    words = text.split()
    return [" ".join(words[i:i + words_per_chunk]) for i in range(0, len(words), words_per_chunk)]


# ---------------------------------------------------------------------------
# Task 1a – Input validation, text extraction, and chunking
# ---------------------------------------------------------------------------

def load_and_validate_pdfs(doc1_path, doc2_path):
    documents = [doc1_path, doc2_path]
    extracted_data = {}

    for doc_path in documents:
        if not isinstance(doc_path, str):
            raise TypeError(f"Invalid input type: {doc_path}. Path must be a string.")
        if not os.path.isfile(doc_path):
            raise FileNotFoundError(f"File not found: {doc_path}")
        if not doc_path.lower().endswith('.pdf'):
            raise ValueError(f"Invalid file format: {doc_path}. File must be a PDF.")

        extracted_data[doc_path] = {
            "text": "",
            "tables": []
        }

        try:
            with pdfplumber.open(doc_path) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        extracted_data[doc_path]["text"] += page_text + "\n"
                    page_tables = page.extract_tables()
                    if page_tables:
                        extracted_data[doc_path]["tables"].extend(page_tables)
        except Exception as e:
            raise IOError(f"Failed to open or process the PDF '{doc_path}'. Error: {e}")

    return extracted_data

def format_tables_to_string(tables):
    if not tables:
        return "No tabular data found."

    table_strings = []
    for i, table in enumerate(tables):
        table_strings.append(f"--- Table {i+1} ---")
        for row in table:
            cleaned_row = [
                str(cell).replace('\n', ' ') if cell is not None else ""
                for cell in row
            ]
            table_strings.append(" | ".join(cleaned_row))
    return "\n".join(table_strings)

def chunk_content(text, words_per_chunk=3000):
    """Splits a long text string into smaller chunks to keep the AI focused."""
    if not text:
        return [""]
    words = text.split()
    return [" ".join(words[i:i + words_per_chunk]) for i in range(0, len(words), words_per_chunk)]

# ---------------------------------------------------------------------------
# Tasks 1b, 1c, 1d – Chunked Prompt Generators
# ---------------------------------------------------------------------------

def generate_zero_shot_chunk_prompt(filename, text_chunk, tables_string):
    prompt = f"""You are an expert Cybersecurity Requirements Analyst.
Your task is to analyze a portion of a security document and extract Key Data Elements (KDEs).
KDEs are specific, actionable security specifications (e.g., OAuth 2.0, AES-256, PCI-DSS).

Output ONLY a valid YAML block matching this exact nested structure. Do not output JSON.
```yaml
element1:
  name: "<KDE name>"
  requirements: 
    - "<requirement text 1>"
    - "<requirement text 2>"
element2:
  name: "<KDE name>"
  requirements: 
    - "<requirement text>"
Document: {filename}
Text Chunk:
{text_chunk if text_chunk else "No standard text found."}

Tables (if any):
{tables_string}

Output ONLY the YAML block. Do not add any explanation before or after it.
"""
    return prompt

def generate_few_shot_chunk_prompt(filename, text_chunk, tables_string):
  prompt = f"""You are an expert Cybersecurity Requirements Analyst.
Your task is to analyze a portion of a security document and extract Key Data Elements (KDEs).
KDEs are specific, actionable security specifications (e.g., OAuth 2.0, AES-256, PCI-DSS).

Output ONLY a valid YAML block using the nested structure shown in the examples below. Do not output JSON.

--- EXAMPLE 1 ---
INPUT:
Document: AppSec_Policy_v1.pdf
Text: All external-facing APIs must implement rate limiting. User authentication will be handled via OAuth 2.0. Data at rest must be encrypted using AES-256.

OUTPUT:

YAML
element1:
  name: "API Rate Limiting"
  requirements: 
    - "All external-facing APIs must implement rate limiting."
element2:
  name: "Authentication"
  requirements: 
    - "User authentication will be handled via OAuth 2.0."
element3:
  name: "Encryption at Rest"
  requirements: 
    - "Data at rest must be encrypted using AES-256."
--- END EXAMPLE 1 ---

Now analyze the following real document chunk and output ONLY the YAML block.

Document: {filename}
Text Chunk:
{text_chunk if text_chunk else "No standard text found."}

Tables (if any):
{tables_string}

Output ONLY the YAML block. Do not add any explanation before or after it.
"""
  return prompt

def generate_chain_of_thought_chunk_prompt(filename, text_chunk, tables_string):
  prompt = f"""You are an expert Cybersecurity Requirements Analyst.
Your task is to analyze a portion of a security document and extract Key Data Elements (KDEs).

Think step-by-step using the following reasoning process before producing your final YAML output:
Step 1 – Read the chunk content carefully.
Step 2 – Identify every sentence that describes a concrete security control or compliance requirement.
Step 3 – Assign a short descriptive KDE category name (e.g., "Encryption at Rest").
Step 4 – Write the requirement verbatim or paraphrase it into one clear sentence.

Output your reasoning for each step, then end with a clearly labelled section "FINAL YAML OUTPUT:" containing ONLY the nested YAML block.

YAML structure required:

YAML
element1:
  name: "<KDE name>"
  requirements: 
    - "<requirement text>"
Document: {filename}
Text Chunk:
{text_chunk if text_chunk else "No standard text found."}

Tables (if any):
{tables_string}

Begin your step-by-step reasoning now, then end with "FINAL YAML OUTPUT:" followed by the YAML block only.
"""
  return prompt

# ---------------------------------------------------------------------------
# Task 1e – KDE extraction and YAML output (NO JSON PARSING)
# ---------------------------------------------------------------------------

def extract_and_save_kdes_with_gemma(
    prompt_string,
    document_paths,
    prompt_type="zero_shot",
    model=None,
    tokenizer=None,
):
    model_id = "google/gemma-3-4b-it"

    messages = [
        {"role": "user", "content": [{"type": "text", "text": prompt_string}]}
    ]
    inputs = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        tokenize=True,
        return_dict=True,
        return_tensors="pt",
    ).to(model.device)

    with torch.inference_mode():
        output_ids = model.generate(**inputs, max_new_tokens=1500, do_sample=False)

    new_tokens  = output_ids[0][inputs["input_ids"].shape[-1]:]
    llm_response = tokenizer.decode(new_tokens, skip_special_tokens=True)

    # 1. Extract the YAML block safely
    cot_marker = "FINAL YAML OUTPUT:"
    if cot_marker in llm_response:
        llm_response_for_yaml = llm_response[llm_response.index(cot_marker) + len(cot_marker):]
    else:
        llm_response_for_yaml = llm_response

    yaml_match = re.search(r'```yaml\s*(.*?)\s*```', llm_response_for_yaml, re.DOTALL)
    
    if yaml_match:
        yaml_str = yaml_match.group(1)
    else:
        # Fallback if the LLM forgot the markdown backticks
        yaml_str = llm_response_for_yaml.strip()

    # 2. Convert the YAML string directly into a Python Nested Dictionary
    try:
        nested_dict = yaml.safe_load(yaml_str)
        # If the model returned nothing or just a string, reset it
        if not isinstance(nested_dict, dict):
             print("  [!] LLM output was not a valid dictionary. Storing fallback.")
             nested_dict = {}
    except yaml.YAMLError as e:
        print(f"  [!] YAML Parsing Error: {e}")
        nested_dict = {}

    # 3. Save the perfectly formatted Nested Dictionary directly to a .yaml file
    for doc_path in document_paths:
        base_name        = os.path.basename(doc_path)
        name_without_ext = os.path.splitext(base_name)[0]
        yaml_filename    = f"{name_without_ext}_{prompt_type}.yaml"

        with open(yaml_filename, 'w') as yaml_file:
            # default_flow_style=False ensures the clean block-style output requested in the rubric
            yaml.dump(nested_dict, yaml_file, default_flow_style=False, sort_keys=False)

    return {
        "llm_name":    model_id,
        "prompt_used": prompt_string,
        "prompt_type": prompt_type,
        "llm_output":  llm_response,
    }

# ---------------------------------------------------------------------------
# Task 1f – Collect all LLM outputs and dump to a TEXT file
# ---------------------------------------------------------------------------

def collect_and_dump_llm_outputs(llm_records, output_filename="llm_outputs.txt"):
    if not llm_records:
        raise ValueError("llm_records list is empty – nothing to write.")

    separator = "=" * 80
    with open(output_filename, 'w', encoding='utf-8') as f:
        for i, record in enumerate(llm_records, start=1):
            f.write(f"{separator}\n")
            f.write(f"Record {i} of {len(llm_records)}\n")
            f.write(f"{separator}\n\n")
            f.write("*LLM Name*\n")
            f.write(record.get("llm_name", "N/A") + "\n\n")
            f.write("*Prompt Type*\n")
            f.write(record.get("prompt_type", "N/A") + "\n\n")
            f.write("*Prompt Used*\n")
            f.write(record.get("prompt_used", "N/A") + "\n\n")
            f.write("*LLM Output*\n")
            f.write(record.get("llm_output", "N/A") + "\n\n")
    print(f"\nAll LLM outputs saved to '{output_filename}'.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Removed "static/" assuming the files are in the main Colab directory
    file_1 = "static/cis-r1.pdf"
    file_2 = "static/cis-r2.pdf"
    document_paths = [file_1, file_2]

    try:
        # 1. Load and Validate
        pdf_data = load_and_validate_pdfs(file_1, file_2)
        print("Successfully loaded and validated both documents.\n")

        # 2. Authenticate and Load Model
        # Make sure your Colab Secret is actually named 'HF_TOKEN' and not 'HF-Token'
        hf_token = userdata.get('HF-Token')
        model_id = "google/gemma-3-4b-it"

        print(f"Loading {model_id} onto the A100 GPU...")
        tokenizer = AutoTokenizer.from_pretrained(model_id, token=hf_token)
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            device_map="auto",
            torch_dtype=torch.bfloat16,
            token=hf_token,
        ).eval()

        # 3. Process Chunk by Chunk
        all_llm_records = []

        for doc_path in document_paths:
            base_name = os.path.basename(doc_path)
            print(f"\n========================================")
            print(f"Processing Document: {base_name}")
            print(f"========================================")
            
            full_text = pdf_data[doc_path]["text"]
            text_chunks = chunk_content(full_text, words_per_chunk=3000)
            tables_str = format_tables_to_string(pdf_data[doc_path]["tables"])
            
            for i, chunk in enumerate(text_chunks):
                print(f"\n--- Analyzing Chunk {i+1} of {len(text_chunks)} ---")
                
                # Pass tables only on the first chunk
                chunk_tables = tables_str if i == 0 else "No tabular data in this chunk."
                
                # MATCHING THE EXACT FUNCTION NAMES FROM YOUR SCRIPT
                prompts_to_run = [
                    (generate_zero_shot_chunk_prompt(base_name, chunk, chunk_tables), "zero_shot"),
                    (generate_few_shot_chunk_prompt(base_name, chunk, chunk_tables), "few_shot"),
                    (generate_chain_of_thought_chunk_prompt(base_name, chunk, chunk_tables), "chain_of_thought")
                ]
                
                for prompt_str, ptype in prompts_to_run:
                    print(f"  -> Running {ptype}...")
                    record = extract_and_save_kdes_with_gemma(
                        prompt_string=prompt_str,
                        document_paths=[doc_path], 
                        prompt_type=f"{ptype}_chunk_{i+1}",
                        model=model,
                        tokenizer=tokenizer,
                    )
                    
                    all_llm_records.append(record)
                    
                    # Prevent VRAM buildup
                    torch.cuda.empty_cache()

        # 4. Save results
        collect_and_dump_llm_outputs(all_llm_records, output_filename="llm_outputs.txt")
        print("\nFinished! Refresh the file folder on the left to see your output files.")

    except Exception as error:
        print(f"\nScript failed. Error: {error}")