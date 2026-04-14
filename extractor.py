import os
import re
import json
import yaml
import torch
import pdfplumber
from transformers import AutoTokenizer, AutoModelForCausalLM


# ---------------------------------------------------------------------------
# Task 1a – Input validation and text extraction
# ---------------------------------------------------------------------------

def load_and_validate_pdfs(doc1_path, doc2_path):
    """
    Validates and extracts text and tables from two PDF documents.

    Args:
        doc1_path (str): Path to the first PDF document.
        doc2_path (str): Path to the second PDF document.

    Returns:
        dict: A data structure containing extracted text and tables for each document.
    """
    documents = [doc1_path, doc2_path]
    extracted_data = {}

    for doc_path in documents:
        # 1. Validation: Check if the input is a valid string
        if not isinstance(doc_path, str):
            raise TypeError(f"Invalid input type: {doc_path}. Path must be a string.")

        # 2. Validation: Check if the file actually exists on the system
        if not os.path.isfile(doc_path):
            raise FileNotFoundError(f"File not found: {doc_path}")

        # 3. Validation: Check if the file has a .pdf extension
        if not doc_path.lower().endswith('.pdf'):
            raise ValueError(f"Invalid file format: {doc_path}. File must be a PDF.")

        # Initialize the data structure for this specific document
        extracted_data[doc_path] = {
            "text": "",
            "tables": []
        }

        # 4. Validation & Extraction: Safely attempt to open and read the file
        try:
            with pdfplumber.open(doc_path) as pdf:
                for page in pdf.pages:
                    # Extract standard text
                    page_text = page.extract_text()
                    if page_text:
                        extracted_data[doc_path]["text"] += page_text + "\n"

                    # Extract tables (returns a list of tables, where each table
                    # is a list of rows/columns)
                    page_tables = page.extract_tables()
                    if page_tables:
                        extracted_data[doc_path]["tables"].extend(page_tables)

        except Exception as e:
            # Catches corrupted PDFs, password-protected files, or read
            # permissions issues
            raise IOError(
                f"Failed to open or process the PDF '{doc_path}'. Error: {e}"
            )

    return extracted_data


# Helper function to convert table lists into readable text
def format_tables_to_string(tables):
    if not tables:
        return "No tabular data found."

    table_strings = []
    for i, table in enumerate(tables):
        table_strings.append(f"--- Table {i+1} ---")
        for row in table:
            # Clean up None values that pdfplumber sometimes returns for empty cells
            cleaned_row = [
                str(cell).replace('\n', ' ') if cell is not None else ""
                for cell in row
            ]
            table_strings.append(" | ".join(cleaned_row))
    return "\n".join(table_strings)


# ---------------------------------------------------------------------------
# Task 1b – Zero-shot prompt
# ---------------------------------------------------------------------------

def generate_zero_shot_prompt(extracted_data):
    """
    Constructs a zero-shot prompt string to identify key data elements
    from the extracted PDF data.

    Args:
        extracted_data (dict): The dictionary returned by load_and_validate_pdfs.

    Returns:
        str: A formatted zero-shot prompt ready to be sent to an LLM.
    """
    file_paths = list(extracted_data.keys())
    if len(file_paths) != 2:
        raise ValueError(f"Expected exactly 2 documents, found {len(file_paths)}.")

    doc1_path, doc2_path = file_paths[0], file_paths[1]

    doc1_text   = extracted_data[doc1_path]["text"].strip()
    doc1_tables = format_tables_to_string(extracted_data[doc1_path]["tables"])
    doc2_text   = extracted_data[doc2_path]["text"].strip()
    doc2_tables = format_tables_to_string(extracted_data[doc2_path]["tables"])

    prompt = f"""You are an expert Cybersecurity Requirements Analyst.
Your task is to analyze the text and tabular data extracted from two security
requirements documents and identify the Key Data Elements (KDEs) in EACH document.

KDEs are specific, actionable security specifications such as:
- Authentication and Authorization mechanisms (e.g., OAuth 2.0, MFA, RBAC)
- Cryptographic standards and encryption (e.g., AES-256, TLS 1.3)
- Compliance frameworks and mandates (e.g., NIST 800-53, GDPR, PCI-DSS)
- Infrastructure and network security rules (e.g., WAF configurations, port restrictions)

Analyze each document independently and extract its KDEs. Do NOT compare documents.

Output ONLY a valid JSON object with this exact structure:
{{
  "documents": {{
    "<filename1>": {{
      "key_data_elements": [
        {{"category": "<KDE name>", "requirement": "<requirement text>"}},
        ...
      ]
    }},
    "<filename2>": {{
      "key_data_elements": [
        {{"category": "<KDE name>", "requirement": "<requirement text>"}},
        ...
      ]
    }}
  }}
}}

### Document 1: {doc1_path}
**Extracted Text:**
{doc1_text if doc1_text else "No standard text found."}

**Extracted Tables:**
{doc1_tables}

---

### Document 2: {doc2_path}
**Extracted Text:**
{doc2_text if doc2_text else "No standard text found."}

**Extracted Tables:**
{doc2_tables}

Output ONLY the JSON object. Do not add any explanation before or after it.
"""
    return prompt


# ---------------------------------------------------------------------------
# Task 1c – Few-shot prompt
# ---------------------------------------------------------------------------

def generate_few_shot_prompt(extracted_data):
    """
    Constructs a few-shot prompt string to identify key data elements
    from the extracted PDF data.

    Args:
        extracted_data (dict): The dictionary returned by load_and_validate_pdfs.

    Returns:
        str: A formatted few-shot prompt ready to be sent to an LLM.
    """
    file_paths = list(extracted_data.keys())
    if len(file_paths) != 2:
        raise ValueError(f"Expected exactly 2 documents, found {len(file_paths)}.")

    doc1_path, doc2_path = file_paths[0], file_paths[1]

    doc1_text   = extracted_data[doc1_path]["text"].strip()
    doc1_tables = format_tables_to_string(extracted_data[doc1_path]["tables"])
    doc2_text   = extracted_data[doc2_path]["text"].strip()
    doc2_tables = format_tables_to_string(extracted_data[doc2_path]["tables"])

    prompt = f"""You are an expert Cybersecurity Requirements Analyst.
Your task is to analyze text and tabular data extracted from two security
requirements documents and identify their Key Data Elements (KDEs).

KDEs are specific, actionable security specifications such as:
- Authentication and Authorization mechanisms (e.g., OAuth 2.0, MFA, RBAC)
- Cryptographic standards and encryption (e.g., AES-256, TLS 1.3)
- Compliance frameworks and mandates (e.g., NIST 800-53, GDPR, PCI-DSS)
- Infrastructure and network security rules (e.g., WAF configurations, port restrictions)

Analyze each document independently. Do NOT compare documents.
Output ONLY a valid JSON object using the structure shown in the examples below.

### --- EXAMPLE 1 --- ###
INPUT:
Document 1: AppSec_Policy_v1.pdf
Text: All external-facing APIs must implement rate limiting. User authentication
will be handled via OAuth 2.0. Data at rest must be encrypted using AES-256.
Tables: No tabular data found.

Document 2: Network_Architecture_Reqs.pdf
Text: The production environment must strictly adhere to PCI-DSS compliance standards.
Tables:
--- Table 1 ---
Component | Inbound Protocol | Required Security
Load Balancer | HTTPS | TLS 1.3 minimum
Internal DB | TCP | Mutual TLS (mTLS)

OUTPUT:
```json
{{
  "documents": {{
    "AppSec_Policy_v1.pdf": {{
      "key_data_elements": [
        {{"category": "API Rate Limiting", "requirement": "All external-facing APIs must implement rate limiting."}},
        {{"category": "Authentication", "requirement": "User authentication will be handled via OAuth 2.0."}},
        {{"category": "Encryption at Rest", "requirement": "Data at rest must be encrypted using AES-256."}}
      ]
    }},
    "Network_Architecture_Reqs.pdf": {{
      "key_data_elements": [
        {{"category": "Compliance", "requirement": "The production environment must strictly adhere to PCI-DSS compliance standards."}},
        {{"category": "Transport Security", "requirement": "Load Balancer inbound HTTPS traffic requires TLS 1.3 minimum."}},
        {{"category": "Transport Security", "requirement": "Internal DB inbound TCP traffic requires Mutual TLS (mTLS)."}}
      ]
    }}
  }}
}}
```

### --- END EXAMPLE 1 --- ###

Now analyze the following real documents and output ONLY the JSON object.

### Document 1: {doc1_path}
**Extracted Text:**
{doc1_text if doc1_text else "No standard text found."}

**Extracted Tables:**
{doc1_tables}

---

### Document 2: {doc2_path}
**Extracted Text:**
{doc2_text if doc2_text else "No standard text found."}

**Extracted Tables:**
{doc2_tables}

Output ONLY the JSON object. Do not add any explanation before or after it.
"""
    return prompt


# ---------------------------------------------------------------------------
# Task 1d – Chain-of-thought prompt
# ---------------------------------------------------------------------------

def generate_chain_of_thought_prompt(extracted_data):
    """
    Constructs a chain-of-thought prompt string to identify key data elements
    from the extracted PDF data.

    Args:
        extracted_data (dict): The dictionary returned by load_and_validate_pdfs.

    Returns:
        str: A formatted chain-of-thought prompt ready to be sent to an LLM.
    """
    file_paths = list(extracted_data.keys())
    if len(file_paths) != 2:
        raise ValueError(f"Expected exactly 2 documents, found {len(file_paths)}.")

    doc1_path, doc2_path = file_paths[0], file_paths[1]

    doc1_text   = extracted_data[doc1_path]["text"].strip()
    doc1_tables = format_tables_to_string(extracted_data[doc1_path]["tables"])
    doc2_text   = extracted_data[doc2_path]["text"].strip()
    doc2_tables = format_tables_to_string(extracted_data[doc2_path]["tables"])

    prompt = f"""You are an expert Cybersecurity Requirements Analyst.
Your task is to analyze text and tabular data extracted from two security
requirements documents and identify their Key Data Elements (KDEs).

KDEs are specific, actionable security specifications such as:
- Authentication and Authorization mechanisms (e.g., OAuth 2.0, MFA, RBAC)
- Cryptographic standards and encryption (e.g., AES-256, TLS 1.3)
- Compliance frameworks and mandates (e.g., NIST 800-53, GDPR, PCI-DSS)
- Infrastructure and network security rules (e.g., WAF configurations, port restrictions)

Think step-by-step using the following reasoning process before producing your
final JSON output. Follow EVERY step for EACH document separately.

Step 1 – Read the document content carefully (text and tables).
Step 2 – Identify every sentence or table cell that describes a concrete security
          control, standard, policy, or compliance requirement.
Step 3 – For each identified sentence/cell, assign a short descriptive KDE category
          name (e.g., "Encryption at Rest", "Access Control", "Compliance Framework").
Step 4 – Write the requirement verbatim or paraphrase it into one clear sentence.
Step 5 – Repeat Steps 1-4 for the second document independently.
Step 6 – Compile all findings into the JSON structure shown below.

Output your reasoning for each step (you may keep it concise), then end with a
clearly labelled section "FINAL JSON OUTPUT:" containing ONLY the JSON object.

JSON structure required:
{{
  "documents": {{
    "<filename1>": {{
      "key_data_elements": [
        {{"category": "<KDE name>", "requirement": "<requirement text>"}},
        ...
      ]
    }},
    "<filename2>": {{
      "key_data_elements": [
        {{"category": "<KDE name>", "requirement": "<requirement text>"}},
        ...
      ]
    }}
  }}
}}

### Document 1: {doc1_path}
**Extracted Text:**
{doc1_text if doc1_text else "No standard text found."}

**Extracted Tables:**
{doc1_tables}

---

### Document 2: {doc2_path}
**Extracted Text:**
{doc2_text if doc2_text else "No standard text found."}

**Extracted Tables:**
{doc2_tables}

Begin your step-by-step reasoning now, then end with "FINAL JSON OUTPUT:" followed
by the JSON object only.
"""
    return prompt


# ---------------------------------------------------------------------------
# Task 1e – KDE extraction with Gemma-3-1B and YAML output
# ---------------------------------------------------------------------------

def extract_and_save_kdes_with_gemma(prompt_string, document_paths, prompt_type="zero_shot"):
    """
    Passes the prompt to Gemma-3-1B, parses the JSON output, groups the
    requirements by KDE, and saves the results into separate YAML files for
    each document.

    Args:
        prompt_string  (str):  The prompt generated by one of the prompt functions.
        document_paths (list): A list containing the two original file paths.
        prompt_type    (str):  Label for this prompt ('zero_shot', 'few_shot',
                               or 'chain_of_thought'). Used in the log file.

    Returns:
        dict: {
            "llm_name":    str,
            "prompt_used": str,
            "prompt_type": str,
            "llm_output":  str,
        }
        – ready to be collected by collect_and_dump_llm_outputs().
    """
    model_id = "google/gemma-3-1b"
    print(f"Loading {model_id} (this may take a moment)...")

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForCausalLM.from_pretrained(
        model_id, device_map="auto", torch_dtype=torch.float16
    )

    print("Generating response from LLM...")
    inputs = tokenizer(prompt_string, return_tensors="pt").to(model.device)
    outputs = model.generate(**inputs, max_new_tokens=1500, temperature=0.1)
    llm_response = tokenizer.decode(outputs[0], skip_special_tokens=True)

    # --- Extract JSON from LLM output ---
    # For chain-of-thought the JSON comes after "FINAL JSON OUTPUT:"
    cot_marker = "FINAL JSON OUTPUT:"
    if cot_marker in llm_response:
        llm_response_for_json = llm_response[llm_response.index(cot_marker) + len(cot_marker):]
    else:
        llm_response_for_json = llm_response

    json_match = re.search(r'```json\s*(.*?)\s*```', llm_response_for_json, re.DOTALL)

    if not json_match:
        # Fallback: find the outermost { ... }
        start_idx = llm_response_for_json.find('{')
        end_idx   = llm_response_for_json.rfind('}')
        if start_idx != -1 and end_idx != -1:
            json_str = llm_response_for_json[start_idx:end_idx + 1]
        else:
            raise ValueError(
                "Failed to extract valid JSON from the LLM response.\n"
                "Response:\n" + llm_response
            )
    else:
        json_str = json_match.group(1)

    try:
        extracted_json = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"LLM output was not valid JSON. Error: {e}\n"
            f"Extracted string:\n{json_str}"
        )

    # --- Restructure and Export to YAML ---
    print("Parsing successful. Generating YAML files...")
    documents_data = extracted_json.get("documents", {})

    for doc_path in document_paths:
        base_name        = os.path.basename(doc_path)
        name_without_ext = os.path.splitext(base_name)[0]
        yaml_filename    = f"{name_without_ext}-kdes.yaml"

        doc_json_data = documents_data.get(base_name)
        if not doc_json_data:
            print(
                f"Warning: The LLM did not return data for '{base_name}'. "
                "Skipping YAML creation."
            )
            continue

        raw_kdes = doc_json_data.get("key_data_elements", [])

        # Group requirements by category name
        grouped_kdes = {}
        for item in raw_kdes:
            cat_name = item.get("category", "Uncategorized")
            req_text = item.get("requirement", "Unknown requirement")
            grouped_kdes.setdefault(cat_name, []).append(req_text)

        # Build the target structure
        final_yaml_structure = {}
        for element_counter, (category, requirements) in enumerate(
            grouped_kdes.items(), start=1
        ):
            final_yaml_structure[f"element{element_counter}"] = {
                "name": category,
                "requirements": requirements,
            }

        with open(yaml_filename, 'w') as yaml_file:
            yaml.dump(
                final_yaml_structure,
                yaml_file,
                default_flow_style=False,
                sort_keys=False,
            )
        print(f"Saved KDEs for '{base_name}' → {yaml_filename}")

    # Return a record for the log file
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
    """
    Collects the output records from one or more LLM runs and writes them
    to a formatted TEXT file.

    Args:
        llm_records     (list[dict]): List of dicts returned by
                                      extract_and_save_kdes_with_gemma().
                                      Each dict must contain:
                                        'llm_name', 'prompt_used',
                                        'prompt_type', 'llm_output'.
        output_filename (str):        Name of the output text file.
                                      Defaults to 'llm_outputs.txt'.
    """
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

    print(f"All LLM outputs saved to '{output_filename}'.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    file_1 = "static/cis-r1.pdf"
    file_2 = "static/cis-r2.pdf"
    document_paths = [file_1, file_2]

    try:
        # Task 1a – load and validate
        pdf_data = load_and_validate_pdfs(file_1, file_2)
        print("Successfully loaded and validated both documents.\n")

        # Task 1b/c/d – build prompts
        zero_shot_prompt  = generate_zero_shot_prompt(pdf_data)
        few_shot_prompt   = generate_few_shot_prompt(pdf_data)
        cot_prompt        = generate_chain_of_thought_prompt(pdf_data)

        # Task 1e – run Gemma-3-1B for each prompt and collect records
        # NOTE: All three calls load the model; if GPU memory is limited,
        # consider calling them sequentially or sharing the model instance.
        llm_records = []

        record_zs = extract_and_save_kdes_with_gemma(
            zero_shot_prompt, document_paths, prompt_type="zero_shot"
        )
        llm_records.append(record_zs)

        record_fs = extract_and_save_kdes_with_gemma(
            few_shot_prompt, document_paths, prompt_type="few_shot"
        )
        llm_records.append(record_fs)

        record_cot = extract_and_save_kdes_with_gemma(
            cot_prompt, document_paths, prompt_type="chain_of_thought"
        )
        llm_records.append(record_cot)

        # Task 1f – dump all outputs to a text file
        collect_and_dump_llm_outputs(llm_records, output_filename="llm_outputs.txt")

    except (TypeError, FileNotFoundError, ValueError, IOError) as error:
        print(f"Error: {error}")