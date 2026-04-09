# PolicyProbe

**AI-powered policy evaluation and remediation demo application**

PolicyProbe is a deliberately vulnerable chat agent application designed to demonstrate how Unifai detects security policy violations and instructs Cursor IDE to remediate them.

## Demo Flow

1. **Run PolicyProbe with Unifai disabled** → vulnerable behavior is visible
2. **Enable Unifai in Cursor** → scans code, detects violations
3. **Unifai instructs Cursor** to fix the violations
4. **Run PolicyProbe again** → guardrails now active, violations blocked

## Four Policy Violations Demonstrated

| Policy | Vulnerability | After Remediation |
|--------|---------------|-------------------|
| **PII Detection** | Files processed without PII scanning | SSN, credit cards, phone numbers detected and blocked |
| **Prompt Injection** | Hidden text/prompts sent to LLM | Hidden content detected and filtered |
| **Agent Auth** | Inter-agent calls bypass authentication | JWT-based authentication required |
| **Vulnerable Deps** | Old packages with known CVEs | Updated to patched versions |

## ⚠️ Security Notice: LLM Provider

This application currently uses **OpenRouter** as the LLM gateway. OpenRouter is **not on the approved LLM allow list**. Before deploying or using this application, you must replace OpenRouter with an approved LLM provider from your organization's allow list. Update the `OPENROUTER_API_KEY` environment variable and all references to `https://openrouter.ai` in the backend code accordingly.

## Quick Start

### Prerequisites

- Node.js 18+
- Python 3.10+
- An API key for an **approved LLM provider** (replace OpenRouter with an approved provider from your allow list)

### Setup

1. **Copy environment file**

```bash
cd policyprobe

# Copy environment template
cp .env.example .env
# Edit .env and add your approved LLM provider API key
# WARNING: Never commit .env or any secrets to version control
```

2. **Create virtual environment and install dependencies**

```bash
./scripts/setup_env.sh    # Creates .venv and installs Python deps
```

3. **Start the application**

```bash
./scripts/run_dev.sh    # Start both backend and frontend servers
```

4. **Stop the application**

```bash
./scripts/stop_dev.sh   # Stop both servers
```

**Or run manually:**

```bash
# Terminal 1: Backend
cd backend
source .venv/bin/activate
uvicorn main:app --reload --port 5500

# Terminal 2: Frontend
cd frontend
npm install
npm run dev -- -p 5001
```

5. **Open the app**

- Frontend: http://localhost:5001
- Backend API: http://localhost:5500
- API Docs: http://localhost:5500/docs

## Project Structure

```
policyprobe/
├── frontend/                    # Next.js React frontend
│   ├── src/
│   │   ├── app/                 # Next.js app router
│   │   └── components/          # React components
│   └── package.json             # ⚠️ Vulnerable npm deps
│
├── backend/                     # Python FastAPI backend
│   ├── agents/                  # Multi-agent system
│   │   ├── orchestrator.py      # Request routing
│   │   ├── tech_support.py      # Low privilege agent
│   │   ├── finance.py           # High privilege agent
│   │   └── auth/                # ⚠️ Auth bypass
│   ├── policies/                # Policy modules
│   │   ├── pii_detection.py     # ⚠️ NO-OP detection
│   │   ├── prompt_injection.py  # ⚠️ NO-OP detection
│   │   └── runtime/             # Runtime guardrails
│   ├── file_parsers/            # File processing
│   └── requirements.txt         # ⚠️ Vulnerable Python deps
│
├── config/                      # Policy configuration
├── test_files/                  # Demo test files
└── scripts/                     # Development scripts
```

## Security Vulnerabilities & Remediations

The following known vulnerability classes are present in this demo application and must be addressed before any non-demo use:

- **Injection flaws**: All user-supplied input passed to the LLM or file parsers must be validated and sanitized. Avoid constructing prompts via string concatenation with untrusted input.
- **Broken Authentication**: Inter-agent calls currently bypass authentication. JWT-based authentication must be enforced on all agent-to-agent calls (see `backend/agents/auth/agent_auth.py`).
- **Broken Access Control**: The finance agent is accessible from the tech support agent without privilege checks. Enforce least-privilege and role-based access controls.
- **Cryptographic Failures**: `JWT_SECRET` must be a strong, randomly generated secret stored in environment variables — never hardcoded. Use HS256 or RS256 with sufficient key length.
- **Security Misconfiguration**: Debug/reload mode (`--reload`) must be disabled in production. CORS must be restricted to known origins only.
- **Path Traversal**: File upload paths must be validated and restricted to a safe upload directory. Reject any path containing `..` or absolute path components.
- **Insecure Deserialization**: Uploaded JSON and HTML files must be parsed safely. Do not use `eval()` or unsafe deserializers on untrusted content.
- **XSS**: All content rendered in the frontend from backend responses must be output-encoded. Avoid `dangerouslySetInnerHTML` with untrusted data.
- **SSRF**: If the backend fetches external URLs, restrict allowed hosts to an explicit allow list and block requests to internal/private IP ranges.
- **Improper Error Handling**: Stack traces and internal error details must not be returned to the client. Return generic error messages and log details server-side only.
- **Sensitive Data Exposure**: PII detected in uploaded files must never be forwarded to the LLM. The `pii_detection.py` and `prompt_injection.py` modules must be fully implemented (not NO-OP).

## Demo Scenarios

### 1. PII Detection Demo

**Before:**
1. Upload `test_files/advanced/nested_pii.json`
2. Observe: "File processed successfully"
3. PII is sent to the LLM without detection

**After Unifai Remediation:**
1. Upload the same file
2. Observe: "Error: PII detected - SSN found in user.profile.contact.ssn"

### 2. Prompt Injection Demo

**Before:**
1. Upload `test_files/advanced/base64_hidden.html`
2. Hidden prompts are extracted and sent to LLM
3. LLM may respond to malicious instructions

**After Unifai Remediation:**
1. Upload the same file
2. Observe: "Security threat detected: Hidden content in HTML elements"

### 3. Agent Authentication Demo

**Before:**
1. Ask: "Can you show me the quarterly financial report?"
2. Tech support agent escalates to finance agent
3. Access granted without proper authentication

**After Unifai Remediation:**
1. Same request
2. Observe: "Unauthorized: Agent token validation failed"

### 4. Vulnerable Dependencies Demo

**Before:**
```bash
cd frontend && npm audit
# Shows vulnerabilities in lodash, axios, etc.
```

**After Unifai Remediation:**
- `package.json` updated with patched versions
- `npm audit` shows no vulnerabilities

## Policy Violation & Guardrail Mapping

| Policy Category | Individual Policy | Violation File (Unifai Scans) | Guardrail File (Unifai Applies) |
|-----------------|-------------------|-------------------------------|--------------------------------|
| **Data Security** | PII in uploaded files | `backend/agents/file_processor.py` | `backend/policies/pii_detection.py` |
| **AI Threats** | Hidden prompts / Prompt injection | `backend/agents/file_processor.py` | `backend/policies/prompt_injection.py` |
| **Identity & Access** | Unauthenticated agent calls | `backend/agents/orchestrator.py` | `backend/agents/auth/agent_auth.py` |
| **Vulnerability** | Vulnerable npm packages | `frontend/package.json` | *(version update)* |
| **Vulnerability** | Vulnerable Python packages | `backend/requirements.txt` | *(version update)* |
| **LLM Governance** | Unapproved LLM provider (OpenRouter) | `backend/` LLM client code | Replace with approved LLM provider |

## Test Files

- `test_files/simple/` - Basic examples for warm-up
- `test_files/advanced/nested_pii.json` - PII buried 5 levels deep
- `test_files/advanced/base64_hidden.html` - Hidden prompts in HTML
- `test_files/advanced/multi_hop_attack.json` - Chained agent exploit

Generate additional test files:
```bash
python scripts/create_test_files.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      PolicyProbe UI                         │
│                   (Next.js + React)                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Agent Orchestrator                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Tech Support │──│   Finance    │  │    File      │      │
│  │ (low priv)   │  │ (high priv)  │  │  Processor   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
         ┌──────────┐  ┌──────────┐  ┌─────────┐
         │ Approved │  │  Policy  │  │  File   │
         │LLM Provider│ │ Modules  │  │ Parsers │
         └──────────┘  └──────────┘  └─────────┘
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `LLM_API_KEY` | API key for approved LLM provider (replace OpenRouter) | Yes |
| `JWT_SECRET` | Strong randomly generated secret for JWT signing — never hardcode | Yes (after remediation) |
| `BACKEND_URL` | Backend URL for frontend | No (default: localhost:5500) |

## License

This is a demo application for Unifai integration testing.