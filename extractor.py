import pdfplumber
import os

def extract_multiple(pdf_paths):
    """
    Validates input and extracts multiple PDFs into a structured dictionary.

    :param pdf_paths: A list of file paths to the PDFs.
    :return: A dictionary where keys are filenames and values are the extracted content.
    """
    
    # Validate that the input is a list
    if not isinstance(pdf_paths, list):
        raise TypeError(f"Expected a list of file paths, got {type(pdf_paths).__name__}")

    # Dictionary of all documents where doc_name is key and content is the value
    all_documents = {}

    for pdf_path in pdf_paths:
        # Validate if file exists
        if not os.path.exists(pdf_path):
            print(f"Warning: File not found: {pdf_path}")
            continue
        
        # Validate if file is a pdf
        if not pdf_path.lower().endswith(".pdf"):
            print(f"Warning: Not a PDF file: {pdf_path}")
            continue
            
        # Validate that the file is not empty
        if os.path.getsize(pdf_path) == 0:
            print(f"Warning: File is empty: {pdf_path}")
            continue

        doc_name = os.path.basename(pdf_path)
        doc = {
            "doc_name": doc_name,
            "pages": []
        }

        # Safely attempt to open and read the PDF
        try:
            with pdfplumber.open(pdf_path) as pdf:
                for i, page in enumerate(pdf.pages):
                    # Extract standard text
                    text = page.extract_text()
                    text = text.strip() if text else ""

                    # Extract tables (Returns a list of tables, where each table is a list of rows, and each row is a list of cells)
                    tables = page.extract_tables()

                    # Clean up table data (replace None with empty strings for easier downstream processing)
                    cleaned_tables = []
                    for table in tables:
                        cleaned_table = [[cell if cell is not None else "" for cell in row] for row in table]
                        cleaned_tables.append(cleaned_table)

                    doc["pages"].append({
                        "page_num": i + 1,
                        "text": text,
                        "tables": cleaned_tables,
                        "table_count": len(cleaned_tables)
                    })
            
            all_documents[doc_name] = doc
            
        except Exception as e:
            print(f"Error processing '{pdf_path}': {e}")

    return all_documents

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



if __name__ == "__main__":
    print("Loading documents...")
    
    target_files = ["static/cis-r1.pdf", "static/cis-r2.pdf"]
    extracted_data = extract_multiple(target_files)
    
    for filename, content in extracted_data.items():
        print(f"\nDocument: {filename}\n" + "=" * 60)
        
        if content["pages"]:
            first_page = content["pages"][0]
            snippet = first_page["text"][:150].replace('\n', ' ')
            
            print(f"Total Pages: {len(content['pages'])}")
            print(f"Page 1 Text Snippet: {snippet}...")
            print(f"Page 1 Table Count: {first_page['table_count']}")
            
            if first_page['table_count'] > 0:
                print(f"First Table on Page 1: {first_page['tables'][0]}")
        else:
            print("No data could be extracted from this document.")