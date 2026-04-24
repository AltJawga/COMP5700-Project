import os
import re

import pdfplumber
import torch
import yaml
from transformers import AutoTokenizer, AutoModelForCausalLM

try:
    from google.colab import userdata
except ImportError:
    userdata = None


# ---------------------------------------------------------------------------
# Task 1a – Input validation and text extraction
# ---------------------------------------------------------------------------

def load_and_validate_pdfs(doc1_path, doc2_path):
    """
    Validates that both paths point to readable PDF files, then extracts
    all text and tables from each.  Returns a dict keyed by file path.
    """
    documents = [doc1_path, doc2_path]
    extracted_data = {}

    for doc_path in documents:
        if not isinstance(doc_path, str):
            raise TypeError(f"Invalid input type: {doc_path!r}. Path must be a string.")
        if not os.path.isfile(doc_path):
            raise FileNotFoundError(f"File not found: {doc_path}")
        if not doc_path.lower().endswith(".pdf"):
            raise ValueError(f"Invalid file format: {doc_path}. File must be a PDF.")

        extracted_data[doc_path] = {"text": "", "tables": []}

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
            raise IOError(f"Failed to open or process '{doc_path}': {e}")

    return extracted_data


def format_tables_to_string(tables):
    """Converts a list of pdfplumber tables into a readable plain-text block."""
    if not tables:
        return "No tabular data found."

    table_strings = []
    for i, table in enumerate(tables):
        table_strings.append(f"--- Table {i + 1} ---")
        for row in table:
            cleaned_row = [
                str(cell).replace("\n", " ") if cell is not None else ""
                for cell in row
            ]
            table_strings.append(" | ".join(cleaned_row))
    return "\n".join(table_strings)


def chunk_content(text, words_per_chunk=3000):
    """Splits a long text string into word-count-bounded chunks."""
    if not text:
        return [""]
    words = text.split()
    return [
        " ".join(words[i: i + words_per_chunk])
        for i in range(0, len(words), words_per_chunk)
    ]


# ---------------------------------------------------------------------------
# Tasks 1b, 1c, 1d – Prompt generators (one chunk at a time)
# ---------------------------------------------------------------------------

def generate_zero_shot_chunk_prompt(filename, text_chunk, tables_string):
    """Zero-shot prompt: no examples, direct instruction."""
    return f"""You are an expert Cybersecurity Requirements Analyst.
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
    ```
    
    Document: {filename}
    Text Chunk:
    {text_chunk if text_chunk else "No standard text found."}
    
    Tables (if any):
    {tables_string}
    
    Output ONLY the YAML block. Do not add any explanation before or after it.
    """


def generate_few_shot_chunk_prompt(filename, text_chunk, tables_string):
    """Few-shot prompt: one worked example followed by the real chunk."""
    return f"""You are an expert Cybersecurity Requirements Analyst.
    Your task is to analyze a portion of a security document and extract Key Data Elements (KDEs).
    KDEs are specific, actionable security specifications (e.g., OAuth 2.0, AES-256, PCI-DSS).
    
    Output ONLY a valid YAML block using the nested structure shown in the example below.
    
    --- EXAMPLE ---
    INPUT:
    Document: AppSec_Policy_v1.pdf
    Text: All external-facing APIs must implement rate limiting. User authentication will be
    handled via OAuth 2.0. Data at rest must be encrypted using AES-256.
    
    OUTPUT:
    ```yaml
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
    ```
    --- END EXAMPLE ---
    
    Now analyze the following document chunk and output ONLY the YAML block.
    
    Document: {filename}
    Text Chunk:
    {text_chunk if text_chunk else "No standard text found."}
    
    Tables (if any):
    {tables_string}
    
    Output ONLY the YAML block. Do not add any explanation before or after it.
    """


def generate_chain_of_thought_chunk_prompt(filename, text_chunk, tables_string):
    """Chain-of-thought prompt: explicit reasoning steps before final YAML."""
    return f"""You are an expert Cybersecurity Requirements Analyst.
    Your task is to analyze a portion of a security document and extract Key Data Elements (KDEs).
    
    Think step-by-step using the following reasoning process before producing your final YAML output:
    Step 1 – Read the chunk content carefully.
    Step 2 – Identify every sentence that describes a concrete security control or compliance requirement.
    Step 3 – Assign a short descriptive KDE category name (e.g., "Encryption at Rest").
    Step 4 – Write the requirement verbatim or paraphrase it into one clear sentence.
    
    Output your reasoning for each step, then end with a clearly labelled section
    "FINAL YAML OUTPUT:" containing ONLY the nested YAML block.
    
    Required YAML structure:
    ```yaml
    element1:
      name: "<KDE name>"
      requirements:
        - "<requirement text>"
    ```
    
    Document: {filename}
    Text Chunk:
    {text_chunk if text_chunk else "No standard text found."}
    
    Tables (if any):
    {tables_string}
    
    Begin your step-by-step reasoning now, then end with "FINAL YAML OUTPUT:" followed by the YAML block only.
    """


# ---------------------------------------------------------------------------
# Task 1e – Run one prompt against the model; return the parsed dict + record
# ---------------------------------------------------------------------------

def run_prompt_on_chunk(prompt_string, prompt_type, model, tokenizer, model_id):
    """
    Feeds a single prompt to Gemma, parses the YAML block from the response,
    and returns (nested_dict, record_dict).
    """
    messages = [{"role": "user", "content": [{"type": "text", "text": prompt_string}]}]
    inputs = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        tokenize=True,
        return_dict=True,
        return_tensors="pt",
    ).to(model.device)

    with torch.inference_mode():
        output_ids = model.generate(**inputs, max_new_tokens=1500, do_sample=False)

    new_tokens = output_ids[0][inputs["input_ids"].shape[-1]:]
    llm_response = tokenizer.decode(new_tokens, skip_special_tokens=True)

    # --- extract YAML string ------------------------------------------------
    cot_marker = "FINAL YAML OUTPUT:"
    response_for_yaml = (
        llm_response[llm_response.index(cot_marker) + len(cot_marker):]
        if cot_marker in llm_response
        else llm_response
    )

    yaml_match = re.search(r"```yaml\s*(.*?)\s*```", response_for_yaml, re.DOTALL)
    yaml_str = yaml_match.group(1) if yaml_match else response_for_yaml.strip()

    # --- parse to dict -------------------------------------------------------
    try:
        nested_dict = yaml.safe_load(yaml_str)
        if not isinstance(nested_dict, dict):
            print("    [!] LLM output was not a valid dict. Storing empty fallback.")
            nested_dict = {}
    except yaml.YAMLError as e:
        print(f"    [!] YAML parse error: {e}")
        nested_dict = {}

    record = {
        "llm_name": model_id,
        "prompt_used": prompt_string,
        "prompt_type": prompt_type,
        "llm_output": llm_response,
    }
    return nested_dict, record


def merge_kde_dicts(base_dict, new_dict):
    """
    Merges new_dict into base_dict with non-colliding element keys.
    Keys in new_dict are renamed (element1 → elementN) so nothing is overwritten.
    """
    if not new_dict:
        return
    next_idx = len(base_dict) + 1
    for value in new_dict.values():
        base_dict[f"element{next_idx}"] = value
        next_idx += 1


# ---------------------------------------------------------------------------
# Task 1e (continued) – Full per-document extraction → one YAML per document
# ---------------------------------------------------------------------------

def extract_and_save_kdes_for_document(
        doc_path, pdf_data, model, tokenizer, model_id, output_dir="."
):
    """
    Processes a single document through all three prompt types, chunk by chunk.
    Each prompt type accumulates KDEs across all chunks into one merged dict.
    At the end the three merged dicts are combined under top-level keys and
    written to ONE yaml file:  <docname>-kdes.yaml

    Returns a list of all LLM records produced (for the text dump).
    """
    base_name = os.path.basename(doc_path)
    name_no_ext = os.path.splitext(base_name)[0]

    full_text = pdf_data[doc_path]["text"]
    tables_str = format_tables_to_string(pdf_data[doc_path]["tables"])
    chunks = chunk_content(full_text, words_per_chunk=3000)

    print(f"\n{'=' * 60}")
    print(f"Document : {base_name}  ({len(chunks)} chunk(s))")
    print(f"{'=' * 60}")

    # One accumulator per prompt type
    accumulated = {
        "zero_shot": {},
        "few_shot": {},
        "chain_of_thought": {},
    }
    all_records = []

    prompt_builders = {
        "zero_shot": generate_zero_shot_chunk_prompt,
        "few_shot": generate_few_shot_chunk_prompt,
        "chain_of_thought": generate_chain_of_thought_chunk_prompt,
    }

    # --- outer loop: prompt type; inner loop: chunks -------------------------
    for ptype, builder in prompt_builders.items():
        print(f"\n  Prompt type: {ptype}")
        for i, chunk in enumerate(chunks):
            # Tables are appended only on the first chunk to avoid repetition
            chunk_tables = tables_str if i == 0 else "No tabular data in this chunk."
            prompt_str = builder(base_name, chunk, chunk_tables)

            print(f"    Chunk {i + 1}/{len(chunks)} ...", end=" ", flush=True)
            chunk_dict, record = run_prompt_on_chunk(
                prompt_str, f"{ptype}_chunk_{i + 1}", model, tokenizer, model_id
            )
            print(f"got {len(chunk_dict)} KDE(s)")

            merge_kde_dicts(accumulated[ptype], chunk_dict)
            all_records.append(record)
            torch.cuda.empty_cache()

    # --- build the final combined structure ----------------------------------
    final_yaml_data = {
        "document": base_name,
        "zero_shot_kdes": accumulated["zero_shot"],
        "few_shot_kdes": accumulated["few_shot"],
        "chain_of_thought_kdes": accumulated["chain_of_thought"],
    }

    yaml_filename = os.path.join(output_dir, f"{name_no_ext}-kdes.yaml")
    with open(yaml_filename, "w", encoding="utf-8") as f:
        yaml.dump(final_yaml_data, f, default_flow_style=False, sort_keys=False)
    print(f"\n  Saved: {yaml_filename}")

    return all_records


# ---------------------------------------------------------------------------
# Task 1f – Collect all LLM outputs and dump to a TEXT file
# ---------------------------------------------------------------------------

def collect_and_dump_llm_outputs(llm_records, output_filename="llm_outputs.txt"):
    """Writes every LLM record to a structured plain-text file."""
    if not llm_records:
        raise ValueError("llm_records list is empty – nothing to write.")

    separator = "=" * 80
    with open(output_filename, "w", encoding="utf-8") as f:
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


def run_extraction_pipeline(file_1, file_2):
    document_paths = [file_1, file_2]
    try:
        # 1. Load and validate both PDFs
        pdf_data = load_and_validate_pdfs(file_1, file_2)
        print("Successfully loaded and validated both documents.\n")

        # 2. Authenticate and load model
        hf_token = userdata.get("HF-Token")
        model_id = "google/gemma-3-1b-it"  # as specified in the README

        print(f"Loading {model_id} ...")
        tokenizer = AutoTokenizer.from_pretrained(model_id, token=hf_token)
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            device_map="auto",
            torch_dtype=torch.bfloat16,
            token=hf_token,
        ).eval()

        # 3. Process each document → one YAML file each
        all_llm_records = []

        for doc_path in document_paths:
            records = extract_and_save_kdes_for_document(
                doc_path=doc_path,
                pdf_data=pdf_data,
                model=model,
                tokenizer=tokenizer,
                model_id=model_id,
                output_dir=".",  # saves to the current Colab directory
            )
            all_llm_records.extend(records)

        # 4. Dump all raw LLM outputs to a text file
        def strip_kdes_and_ext(filename):
            base = os.path.splitext(os.path.basename(filename))[0]
            return base.replace('-kdes', '')

        base1 = strip_kdes_and_ext(file_1)
        base2 = strip_kdes_and_ext(file_2)
        output_filename = f"llm_outputs_{base1}_{base2}.txt"
        collect_and_dump_llm_outputs(all_llm_records, output_filename=output_filename)
        print("\nDone! You should now have:")
        print(f"  {base1}-kdes.yaml")
        print(f"  {base2}-kdes.yaml")
        print(f"  {output_filename}")

    except Exception as error:
        import traceback
        traceback.print_exc()
        print(f"\nScript failed: {error}")
