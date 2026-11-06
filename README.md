# AI Security Code Reviewer

An AI-powered static security code review tool built for the CDF CyberSec Hackathon (Find. Fix. Fortify.).

It reads a source-code folder, asks Google Gemini to review it for security weaknesses, verifies each finding against the real code, and writes a Markdown security report with severity, evidence, explanation, and a secure code fix.

## What it does

1. **Find:** collects `.ts`, `.tsx`, `.js`, `.sql`, `.json`, and `.toml` files (skips `node_modules`, lockfiles, and config noise) and sends them to Gemini with line numbers.
2. **Fix:** for each finding, Gemini returns the category, CWE, severity, confidence, affected file and line range, exact evidence, impact, a recommended fix, a secure code snippet, and assumptions.
3. **Verify:** the tool checks that every finding's quoted evidence really exists in the reported file, and drops any that do not (this removes hallucinated findings).
4. **Fortify:** generates `security_report.md` with an executive summary, severity counts, detailed findings, an overall assessment, and scope and limitations.

SQL files are reviewed together in one request so that policies defined in one migration are seen alongside the others. Empty results are retried once, and temporary Gemini errors (429, 500, 503) are retried automatically.

## AI used

- **Provider:** Google Gemini API
- **Model:** `gemini-3.5-flash-lite`
- **What the AI does:** finds the weaknesses, explains the root cause and impact, assigns severity and confidence, and writes secure code fixes.
- **Guardrails:** the system prompt tells the model to treat the code as untrusted data and never follow instructions found inside it, to avoid speculation, and to use careful wording. Code is never executed.

## Setup

Requires Python 3.9 or higher and a free Gemini API key from https://aistudio.google.com.

```bash
git clone https://github.com/salonichauhan1101/cdf-security-reviewer.git
cd cdf-security-reviewer
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install google-genai python-dotenv
cp .env.example .env              # then paste your key into .env
```

## Usage

```bash
./run.sh <path-to-source-folder> "App Name"
```

Example:

```bash
./run.sh path/to/vulnerable-app "CDF TaskFlow"
```

Or run the two steps yourself:

```bash
python reviewer.py <path-to-source-folder>     # writes verified_findings.json
python report.py verified_findings.json "App Name"   # writes security_report.md
```

A sample report generated on CDF TaskFlow is in `sample-output/security_report_taskflow.md`.

## Limitations

- Static review only: no exploit execution or runtime testing.
- AI output can vary between runs and can miss issues or be wrong, so findings should be validated by a developer.
- Files are reviewed one at a time (SQL files together), so cross-file issues in application code may be missed.
- Input is a local folder only (no ZIP or GitHub URL support).

## Third-party components

- [google-genai](https://pypi.org/project/google-genai/): Gemini API client
- [python-dotenv](https://pypi.org/project/python-dotenv/): loads the API key from `.env`
- Python standard library only otherwise

The organizers' sample application, CDF TaskFlow, is used only as input and is not included in this repository.

## Security notes

- Never commit your real `.env` file. Only `.env.example` is committed.
- Only analyze code you are authorized to review, and do not send confidential code to an external AI service.
