import pdfplumber
import yaml
import os
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline

print('successfully imported libraries')
# Input validation and load into dictionary
# Web accessible LLMs state this dictionary structure as optimal for LLM input
def load_docs(pdf_path1, pdf_path2):
    def extract(pdf_path):
        
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"File not found: {pdf_path}")
        
        if not pdf_path.lower().endswith(".pdf"):
            raise ValueError(f"Not a PDF file: {pdf_path}")

        doc = {
            "doc_name": os.path.basename(pdf_path),
            "pages": []
        }

        with pdfplumber.open(pdf_path) as pdf:
            for i, page in enumerate(pdf.pages):
                text = page.extract_text()

                # Handle empty pages
                if text:
                    text = text.strip()
                else:
                    text = ""

                doc["pages"].append({
                    "page_num": i + 1,
                    "text": text
                })
        return doc
    return extract(pdf_path1), extract(pdf_path2)


if __name__ == "__main__":
    print("Loading documents...")
    doc1, doc2 = load_docs("static/cis-r1.pdf", "static/cis-r2.pdf")
    print(doc1, '\n\n', doc2)