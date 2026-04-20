## Zero-Shot Prompt

You are an expert Cybersecurity Requirements Analyst.
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

---

## Few-Shot Prompt

You are an expert Cybersecurity Requirements Analyst.
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

---

## Chain-of-Thought Prompt

You are an expert Cybersecurity Requirements Analyst.
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
