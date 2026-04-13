"""
extractor.py — Task-1: Extractor
Extracts text from CIS benchmark PDFs, builds prompts (zero-shot, few-shot,
chain-of-thought), runs them through Gemma-3-1B to identify Key Data Elements
(KDEs), and saves outputs to YAML and TEXT files.
"""

import os
import re
import yaml
import pdfplumber
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
#from datetime import datetime


# ---------------------------------------------------------------------------
# Function 1 – extract_multiple
# ---------------------------------------------------------------------------

def extract_multiple(pdf_paths):
    """
    Validates input and extracts multiple PDFs into a structured dictionary.

    :param pdf_paths: A list of file paths to the PDFs.
    :return: A dictionary where keys are filenames and values are the
             extracted content (doc_name + pages list).
    :raises TypeError: If pdf_paths is not a list.
    """
    if not isinstance(pdf_paths, list):
        raise TypeError(f"Expected a list of file paths, got {type(pdf_paths).__name__}")

    all_documents = {}

    for pdf_path in pdf_paths:
        if not os.path.exists(pdf_path):
            print(f"Warning: File not found: {pdf_path}")
            continue

        if not pdf_path.lower().endswith(".pdf"):
            print(f"Warning: Not a PDF file: {pdf_path}")
            continue

        if os.path.getsize(pdf_path) == 0:
            print(f"Warning: File is empty: {pdf_path}")
            continue

        doc_name = os.path.basename(pdf_path)
        doc = {"doc_name": doc_name, "pages": []}

        try:
            with pdfplumber.open(pdf_path) as pdf:
                for i, page in enumerate(pdf.pages):
                    text = page.extract_text()
                    text = text.strip() if text else ""

                    tables = page.extract_tables()
                    cleaned_tables = [
                        [[cell if cell is not None else "" for cell in row] for row in table]
                        for table in tables
                    ]

                    doc["pages"].append({
                        "page_num": i + 1,
                        "text": text,
                        "tables": cleaned_tables,
                        "table_count": len(cleaned_tables),
                    })

            all_documents[doc_name] = doc

        except Exception as e:
            print(f"Error processing '{pdf_path}': {e}")

    return all_documents


# ---------------------------------------------------------------------------
# Function 2 – build_zero_shot_prompt
# ---------------------------------------------------------------------------

def build_zero_shot_prompt(doc1_content: dict, doc2_content: dict) -> str:
    """
    Constructs a zero-shot prompt to identify Key Data Elements (KDEs)
    in the two input documents.

    :param doc1_content: Extracted content dict for document 1.
    :param doc2_content: Extracted content dict for document 2.
    :return: A formatted zero-shot prompt string.
    """
    text1 = _get_doc_text(doc1_content)
    text2 = _get_doc_text(doc2_content)

    prompt = (
        "You are a cybersecurity expert analyzing security benchmark documents.\n\n"
        "Identify the Key Data Elements (KDEs) from the two security requirement "
        "documents provided below.\n\n"
        "A Key Data Element is a named configuration, setting, policy, or control "
        "that is explicitly required or recommended in the document. Each KDE should "
        "have a short descriptive name and the associated requirement(s) that reference it.\n\n"
        "Return your answer as a YAML structure with the following format:\n"
        "element1:\n"
        "  name: <short name>\n"
        "  requirements:\n"
        "    - <requirement text>\n\n"
        "--- DOCUMENT 1: {name1} ---\n"
        "{text1}\n\n"
        "--- DOCUMENT 2: {name2} ---\n"
        "{text2}\n\n"
        "Respond with only the YAML output. Do not include any explanation."
    ).format(
        name1=doc1_content.get("doc_name", "Document 1"),
        text1=text1,
        name2=doc2_content.get("doc_name", "Document 2"),
        text2=text2,
    )

    return prompt


# ---------------------------------------------------------------------------
# Function 3 – build_few_shot_prompt
# ---------------------------------------------------------------------------

def build_few_shot_prompt(doc1_content: dict, doc2_content: dict) -> str:
    """
    Constructs a few-shot prompt to identify Key Data Elements (KDEs)
    in the two input documents.

    :param doc1_content: Extracted content dict for document 1.
    :param doc2_content: Extracted content dict for document 2.
    :return: A formatted few-shot prompt string.
    """
    text1 = _get_doc_text(doc1_content)
    text2 = _get_doc_text(doc2_content)

    few_shot_examples = (
        "Example 1:\n"
        "Document excerpt: 'Ensure that the kubelet anonymous authentication is disabled.'\n"
        "Output:\n"
        "element1:\n"
        "  name: kubelet_anonymous_auth\n"
        "  requirements:\n"
        "    - Ensure that the kubelet anonymous authentication is disabled.\n\n"
        "Example 2:\n"
        "Document excerpt: 'Set audit log retention to at least 30 days. "
        "Configure audit log path to a persistent storage location.'\n"
        "Output:\n"
        "element2:\n"
        "  name: audit_log_configuration\n"
        "  requirements:\n"
        "    - Set audit log retention to at least 30 days.\n"
        "    - Configure audit log path to a persistent storage location.\n\n"
        "Example 3:\n"
        "Document excerpt: 'Ensure that the --read-only-port is disabled. "
        "Ensure that the --streaming-connection-idle-timeout is not set to 0.'\n"
        "Output:\n"
        "element3:\n"
        "  name: kubelet_port_settings\n"
        "  requirements:\n"
        "    - Ensure that the --read-only-port is disabled.\n"
        "    - Ensure that the --streaming-connection-idle-timeout is not set to 0.\n\n"
    )

    prompt = (
        "You are a cybersecurity expert analyzing security benchmark documents.\n\n"
        "Your task is to identify Key Data Elements (KDEs) from security requirement "
        "documents. A KDE is a named configuration, setting, policy, or control that "
        "is explicitly required or recommended. Each KDE has a short descriptive name "
        "and the associated requirements.\n\n"
        "Here are examples of how to identify KDEs:\n\n"
        "{examples}"
        "Now analyze the following two documents and extract all KDEs in the same YAML format:\n\n"
        "--- DOCUMENT 1: {name1} ---\n"
        "{text1}\n\n"
        "--- DOCUMENT 2: {name2} ---\n"
        "{text2}\n\n"
        "Respond with only the YAML output. Do not include any explanation."
    ).format(
        examples=few_shot_examples,
        name1=doc1_content.get("doc_name", "Document 1"),
        text1=text1,
        name2=doc2_content.get("doc_name", "Document 2"),
        text2=text2,
    )

    return prompt


# ---------------------------------------------------------------------------
# Function 4 – build_chain_of_thought_prompt
# ---------------------------------------------------------------------------

def build_chain_of_thought_prompt(doc1_content: dict, doc2_content: dict) -> str:
    """
    Constructs a chain-of-thought prompt to identify Key Data Elements (KDEs)
    in the two input documents.

    :param doc1_content: Extracted content dict for document 1.
    :param doc2_content: Extracted content dict for document 2.
    :return: A formatted chain-of-thought prompt string.
    """
    text1 = _get_doc_text(doc1_content)
    text2 = _get_doc_text(doc2_content)

    prompt = (
        "You are a cybersecurity expert analyzing security benchmark documents.\n\n"
        "Follow these reasoning steps to identify Key Data Elements (KDEs) from "
        "the two documents provided:\n\n"
        "Step 1 — Understand what a KDE is: A Key Data Element is a named "
        "configuration setting, security control, policy, or system parameter "
        "that is explicitly required or recommended in the document (e.g., "
        "'anonymous_auth', 'audit_log_path', 'kubelet_authorization_mode').\n\n"
        "Step 2 — Scan Document 1 for requirement statements: Look for sentences "
        "that start with 'Ensure', 'Verify', 'Configure', 'Set', 'Disable', "
        "'Enable', or similar imperative verbs. Each such sentence likely "
        "references a KDE.\n\n"
        "Step 3 — Scan Document 2 for requirement statements: Apply the same "
        "approach to Document 2.\n\n"
        "Step 4 — Group requirements by data element: Requirements that control "
        "the same system setting or security property should be grouped under "
        "one KDE. Assign a short snake_case name to each group.\n\n"
        "Step 5 — Output the result as YAML with this structure:\n"
        "element1:\n"
        "  name: <short_snake_case_name>\n"
        "  requirements:\n"
        "    - <requirement 1>\n"
        "    - <requirement 2>\n\n"
        "Now apply these steps to the documents below.\n\n"
        "--- DOCUMENT 1: {name1} ---\n"
        "{text1}\n\n"
        "--- DOCUMENT 2: {name2} ---\n"
        "{text2}\n\n"
        "Think through each step carefully, then provide only the final YAML output."
    ).format(
        name1=doc1_content.get("doc_name", "Document 1"),
        text1=text1,
        name2=doc2_content.get("doc_name", "Document 2"),
        text2=text2,
    )

    return prompt


# ---------------------------------------------------------------------------
# Function 5 – identify_kdes
# ---------------------------------------------------------------------------

def identify_kdes(
    doc1_content: dict,
    doc2_content: dict,
    prompt_type: str = "zero_shot",
    output_dir: str = ".",
) -> tuple[dict, dict]:
    """
    Uses Gemma-3-1B to identify KDEs from two documents using the specified
    prompt strategy. Saves results to YAML files named after the input documents.

    :param doc1_content: Extracted content dict for document 1.
    :param doc2_content: Extracted content dict for document 2.
    :param prompt_type: One of 'zero_shot', 'few_shot', or 'chain_of_thought'.
    :param output_dir: Directory where YAML files will be saved.
    :return: A tuple (kde_dict1, kde_dict2) of nested KDE dictionaries.
    """
    

    # --- Build the prompt ---
    if prompt_type == "zero_shot":
        prompt = build_zero_shot_prompt(doc1_content, doc2_content)
    elif prompt_type == "few_shot":
        prompt = build_few_shot_prompt(doc1_content, doc2_content)
    elif prompt_type == "chain_of_thought":
        prompt = build_chain_of_thought_prompt(doc1_content, doc2_content)
    else:
        raise ValueError(
            f"Unknown prompt_type '{prompt_type}'. "
            "Choose from: 'zero_shot', 'few_shot', 'chain_of_thought'."
        )

    # --- Load Gemma-3-1B ---
    model_name = "google/gemma-3-1b-it"
    print(f"Loading {model_name}…")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
        device_map="auto",
    )

    # Gemma has a limited context window — truncate the prompt if needed
    max_input_tokens = 7000
    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=max_input_tokens,
    )
    try:
        inputs = inputs.to(model.device)
    except AttributeError:
        pass  # dict-like mock or CPU-only path

    print("Running inference…")
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=1024,
            do_sample=False,
            temperature=1.0,
        )

    # Decode only the newly generated tokens
    try:
        input_len = inputs["input_ids"].shape[-1]
    except (AttributeError, KeyError, TypeError):
        input_len = 0  # mock fallback: decode everything
    generated = tokenizer.decode(
        output_ids[0][input_len:],
        skip_special_tokens=True,
    )

    # --- Parse YAML from the LLM output ---
    kde_dict = _parse_yaml_output(generated)

    # --- Split KDEs per document (heuristic: each doc gets the full set) ---
    kde_dict1 = kde_dict
    kde_dict2 = kde_dict

    # --- Save YAML files ---
    os.makedirs(output_dir, exist_ok=True)
    name1 = _stem(doc1_content.get("doc_name", "doc1"))
    name2 = _stem(doc2_content.get("doc_name", "doc2"))
    yaml_path1 = os.path.join(output_dir, f"{name1}-kdes.yaml")
    yaml_path2 = os.path.join(output_dir, f"{name2}-kdes.yaml")

    with open(yaml_path1, "w", encoding="utf-8") as f:
        yaml.dump(kde_dict1, f, default_flow_style=False, allow_unicode=True)

    with open(yaml_path2, "w", encoding="utf-8") as f:
        yaml.dump(kde_dict2, f, default_flow_style=False, allow_unicode=True)

    print(f"Saved: {yaml_path1}")
    print(f"Saved: {yaml_path2}")

    return kde_dict1, kde_dict2


# ---------------------------------------------------------------------------
# Function 6 – collect_llm_outputs
# ---------------------------------------------------------------------------

def collect_llm_outputs(
    results: list[dict],
    output_path: str = "llm_outputs.txt",
) -> str:
    """
    Collects outputs from all LLM runs and dumps them to a formatted TEXT file.

    Each entry in `results` must contain:
      - llm_name   (str)
      - prompt     (str)
      - prompt_type (str)
      - llm_output (str)

    :param results: List of result dicts from LLM runs.
    :param output_path: Path of the output TEXT file.
    :return: The path of the written file.
    """
    lines = []
    for entry in results:
        lines.append(f"*LLM Name*\n{entry.get('llm_name', 'Unknown')}\n")
        lines.append(f"*Prompt Used*\n{entry.get('prompt', '')}\n")
        lines.append(f"*Prompt Type*\n{entry.get('prompt_type', '')}\n")
        lines.append(f"*LLM Output*\n{entry.get('llm_output', '')}\n")
        lines.append("-" * 80 + "\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Saved LLM outputs to: {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_doc_text(doc_content: dict, max_chars: int = 12000) -> str:
    """
    Concatenates page text from an extracted document dict.
    Truncates to max_chars to avoid blowing out the model context window.
    """
    parts = []
    for page in doc_content.get("pages", []):
        text = page.get("text", "").strip()
        if text:
            parts.append(text)

    full_text = "\n\n".join(parts)
    if len(full_text) > max_chars:
        full_text = full_text[:max_chars] + "\n[... truncated ...]"
    return full_text


def _parse_yaml_output(llm_text: str) -> dict:
    """
    Attempts to parse YAML from the LLM's output.
    Falls back to a minimal structure if parsing fails.
    """
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:yaml)?", "", llm_text).strip()

    try:
        parsed = yaml.safe_load(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except yaml.YAMLError:
        pass

    # Fallback: return raw output wrapped in a dict
    return {"element1": {"name": "unparsed_output", "requirements": [llm_text.strip()]}}


def _stem(filename: str) -> str:
    """Returns the filename without its extension."""
    return os.path.splitext(filename)[0]


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Loading documents…")

    target_files = ["static/cis-r1.pdf", "static/cis-r2.pdf"]
    extracted_data = extract_multiple(target_files)

    for filename, content in extracted_data.items():
        print(f"\nDocument: {filename}\n" + "=" * 60)

        if content["pages"]:
            first_page = content["pages"][0]
            snippet = first_page["text"][:150].replace("\n", " ")

            print(f"Total Pages: {len(content['pages'])}")
            print(f"Page 1 Text Snippet: {snippet}...")
            print(f"Page 1 Table Count: {first_page['table_count']}")

            if first_page["table_count"] > 0:
                print(f"First Table on Page 1: {first_page['tables'][0]}")
        else:
            print("No data could be extracted from this document.")

    if len(extracted_data) == 2:
        docs = list(extracted_data.values())
        doc1, doc2 = docs[0], docs[1]

        # Run all three prompt strategies
        for ptype in ["zero_shot", "few_shot", "chain_of_thought"]:
            print(f"\n--- Running {ptype} extraction ---")
            kde1, kde2 = identify_kdes(doc1, doc2, prompt_type=ptype, output_dir="output")

        print("\nDone.")