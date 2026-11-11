# SecureShip Phase 4: LLM Provider Integration & Verification

## 1. Overview & Dependency Architecture

SecureShip integrates with Large Language Model providers via standard HTTP REST APIs without introducing third-party vendor SDKs (`@anthropic-ai/sdk` or `openai`). All communication is executed using native Node.js `fetch` via a hardened `HttpClient` layer enforcing:

- Request timeouts (60s default)
- Loopback isolation and HTTPS enforcement
- Absolute refusal of HTTP redirects (`redirect: 'error'`)
- Max concurrency controls (default 2 parallel requests)
- Exponential backoff upon encountering HTTP 429 rate limit responses

---

## 2. Official Provider API Documentation Verification

| Provider              | Endpoint                    | Documentation Source                                        |       Status        | Verified Features                                                                                                                                                                                 |
| :-------------------- | :-------------------------- | :---------------------------------------------------------- | :-----------------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Anthropic**         | `POST /v1/messages`         | Official Anthropic Messages API Docs (`docs.anthropic.com`) | **VERIFIED (Docs)** | `anthropic-version: 2023-06-01`, `x-api-key`, system prompt string, `messages: [{ role, content }]`, `max_tokens`, `temperature: 0`. Single retry without temperature on 400 rejection.           |
| **OpenAI-Compatible** | `POST /v1/chat/completions` | Official OpenAI API Reference & Ollama/vLLM specifications  | **VERIFIED (Docs)** | `Authorization: Bearer <token>`, `model`, `messages: [{ role, content }]`, `max_tokens`, `temperature: 0`. Single retry without temperature on 400 rejection. Self-hosted loopback compatibility. |
| **Fake Provider**     | In-Memory Stub              | `@secureship/ai/testing`                                    | **VERIFIED (Code)** | Isolated test provider used for CI and mutation verification. Zero external network egress.                                                                                                       |

---

## 3. Anthropic Messages API Adapter

### Request Specification

- **URL**: `${baseUrl}/v1/messages` (Default baseUrl: `https://api.anthropic.com`)
- **Headers**:
  ```http
  Content-Type: application/json
  x-api-key: <ANTHROPIC_API_KEY | SECURESHIP_AI_API_KEY>
  anthropic-version: 2023-06-01
  ```
- **Body**:
  ```json
  {
    "model": "<user-specified-model>",
    "system": "<PromptBuilder.buildSystemPrompt()>",
    "messages": [
      {
        "role": "user",
        "content": "<PromptBuilder.buildUserPrompt()>"
      }
    ],
    "max_tokens": 1024,
    "temperature": 0
  }
  ```

### Non-Deterministic Fallback Policy (Amendment A6)

If Anthropic returns an HTTP 400 error indicating that the requested model does not support `temperature: 0`, the adapter retries the request exactly once omitting `temperature`. If successful, the result is accepted but flagged with `deterministic: false` in the execution summary and report metadata.

---

## 4. OpenAI-Compatible Chat Completions Adapter

### Supported Engines

The `OpenAiProvider` supports standard OpenAI endpoints as well as self-hosted, private open-source model servers running locally or in private VPCs:

- **Ollama**: `http://localhost:11434/v1`
- **LM Studio**: `http://localhost:1234/v1`
- **vLLM**: `http://localhost:8000/v1`
- **LocalAI**: `http://localhost:8080/v1`
- **OpenAI Cloud**: `https://api.openai.com/v1`

### Request Specification

- **URL**: `${baseUrl}/chat/completions`
- **Headers**:
  ```http
  Content-Type: application/json
  Authorization: Bearer <OPENAI_API_KEY | SECURESHIP_AI_API_KEY>
  ```
- **Body**:
  ```json
  {
    "model": "<user-specified-model>",
    "messages": [
      {
        "role": "system",
        "content": "<PromptBuilder.buildSystemPrompt()>"
      },
      {
        "role": "user",
        "content": "<PromptBuilder.buildUserPrompt()>"
      }
    ],
    "max_tokens": 1024,
    "temperature": 0
  }
  ```

### Non-Deterministic Fallback Policy

Like the Anthropic adapter, if an OpenAI-compatible endpoint (such as an OpenAI reasoning model o1/o3 or custom server) returns an HTTP 400 error indicating that `temperature: 0` is unsupported, the adapter retries the request exactly once omitting `temperature`. If successful, the result is accepted but flagged with `deterministic: false` in the execution summary and report metadata.

> [!NOTE] > **No Default Model**: SecureShip requires explicit configuration of the model name (`--ai-model <name>` or `secureship ai enable --model <name>`). No hardcoded model names exist in the production runtime.

---

## 5. Fake Testing Provider (`@secureship/ai/testing`)

For deterministic unit testing, mutation testing, and offline CI pipelines, SecureShip provides `FakeLlmProvider`:

- Exported exclusively from `@secureship/ai/testing`
- Inaccessible from repository configurations (`secureship.config.json`)
- Excluded from the standard CLI provider selection menu
- Allows testing adversarial model behavior, prompt injection compliance, schema parsing errors, and malformed citations without requiring network calls or real API keys.

---

## 6. Tiering & Deployment Accuracy (Amendment A13)

- **Local & Self-Hosted Open LLMs**: Fully supported and included in the standard Community edition. Users can freely connect SecureShip to local Ollama, LM Studio, or vLLM endpoints.
- **Enterprise Capabilities**: Dedicated air-gapped appliances, managed private enterprise LLM deployments, centralized multi-tenant policy enforcement, and dedicated enterprise SLA support. No runtime license keys or synthetic software locks are compiled into the core engine.
