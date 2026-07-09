# AI-Shield Moderation Layer Architecture

AI-Shield is a **rule-based moderation API gateway** that sanitizes text and file inputs before they reach an LLM.  
It detects **PII, CII, secrets, toxic content, prompt injections**, and validates **files and token sizes** — using configurable JSON rule files.  
No LLM integration. No UI. Pure backend API.

---

## Phase 1: High-Level Overview
- Accepts **text and file uploads** (PDF, DOCX, TXT, JSON).
- Individual APIs for each detector:
  - PII Detector
  - CII Detector
  - Secrets Detector
  - Toxicity Detector
  - Prompt Injection Detector
  - File Validator
  - Token Size Validator
- Configurable execution order, decisions, masking strategies, logging levels.
- Admin API for rule reloading.
- API key authentication at gateway.
- Deployment options: single instance, Docker, Kubernetes, serverless.

---

## Phase 2: Detailed API Design
| Detector | Endpoint | Description |
|----------|----------|-------------|
| PII | `/moderation/pii` | Detects and masks personally identifiable information |
| CII | `/moderation/cii` | Detects and masks confidential information |
| Secrets | `/moderation/secrets` | Detects and blocks secrets or credentials |
| Toxicity | `/moderation/toxicity` | Detects toxic content and masks or blocks |
| Prompt Injection | `/moderation/prompt-injection` | Detects prompt injection attempts |
| File Validator | `/moderation/file-validator` | Validates file type, MIME, and size |
| Token Validator | `/moderation/token-validator` | Enforces token size limits |
| Admin | `/admin/rules/reload` | Reloads JSON rule files dynamically |

---

## Phase 3: JSON Configuration Examples
- **Execution Order & Pipeline Config**
```json
{ 
  "executionOrder": ["FileValidator","TokenValidator","PII","CII","Secrets","Toxicity","PromptInjection"] 
}
```

- **Detector Rules (with Fail-Safe and Context Policies)**
```json
{
  "detectors": {
    "PII": { 
      "action": "mask", 
      "maskingStrategy": "[PII_MASKED]",
      "failOpen": false 
    },
    "Secrets": { 
      "action": "block",
      "failOpen": false 
    },
    "Toxicity": { 
      "action": "mask", 
      "maskingStrategy": "[TOXIC_CONTENT]",
      "failOpen": true 
    }
  }
}
```

- **Rate Limiting Configuration**
```json
{
  "rateLimiter": {
    "windowMs": 60000,
    "maxRequests": 100,
    "policy": "reject"
  }
}
```

- **File Validator**
```json
{ "fileValidator": { "allowedTypes":["pdf","docx"], "mimeCheck":true, "maxSizeMB":10, "policy":"reject" } }
```

- **Token Validator**
```json
{ "tokenValidator": { "maxTokens":4096, "policy":"reject" } }
```

- **Logging**
```json
{ "logging": { "level":"UNSAFE_ONLY", "format":"json", "destination":"logs/moderation.log" } }
```

- **Deployment**
```json
{ "deployment": { "strategy":"docker", "replicas":3, "autoscale":true } }
```

---

## Phase 4: End-to-End Flow
1. **Client Request** → API Gateway (Auth)  
2. **File Validator** → Validate file structure, size, and MIME type.  
3. **Text Extraction Layer** → If request contains a file, extract raw text (PDF/DOCX/TXT/JSON).  
4. **Token Validator** → Validate token counts against limits (early reject if threshold exceeded).  
5. **Parallel Moderation Pipeline** → Run independent checks concurrently:  
   - *PII Detector* (Regex + Entity Analysis)  
   - *CII Detector* (Contextual Corporate Rules)  
   - *Secrets Detector* (High-Entropy Scanning + Key Patterns)  
   - *Toxicity Detector* (Semantic Toxicity Scoring)  
   - *Prompt Injection Detector* (Semantic Threat Analysis)  
6. **Decision Engine & Aggregator** → Consolidate outcomes, apply action mapping (mask/block/allow).  
7. **Logging Service** → Log security event metadata (strictly redacting any sensitive data to preserve GDPR/HIPAA compliance).  
8. **Response** → Final safe output or rejection response.  

---

## Phase 5: Component-Level Architecture
*   **API Gateway** → Handles client authentication (API Key) and routing.
*   **File Validator Service** → Checks metadata, MIME integrity, and sizes.
*   **Text Extraction Service** → Extracts clean textual content from multi-format files.
*   **Token Validator Service** → Enforces maximum token window sizes.
*   **Pipeline Aggregator (Chain/Pipeline Pattern)** → Coordinates the registration, ordering, and execution of detector modules.
*   **Detector Services (Decoupled Middleware modules):**
    *   *PII Service* → Dual-stage regex and Microsoft Presidio-like entity masking.
    *   *CII Service* → Context-aware scanner for corporate intellectual property.
    *   *Secrets Service* → Entropy scanner detecting SSH/API keys.
    *   *Toxicity Service* → Offloads text classification to worker threads.
    *   *Prompt Injection Service* → Semantic classifier checking inputs for system prompt escapes.
*   **Decision Engine** → Applies config rules (allow/mask/block) and constructs the final output.
*   **Compliance Logging Service** → Writes audit trail logs containing payload hashes/metadata only, strictly avoiding log leakage of PII/secrets.
*   **Admin Rules Service** → Watches configurations (via K8s ConfigMaps or Redis Pub/Sub) for real-time, multi-replica state synchronization.

---

## Phase 6: Technology Stack

| Layer         | Technology                        | Architectural Note |
|---------------|-----------------------------------|--------------------|
| Runtime       | Node.js (20.x LTS, `npm run dev`) | Single-threaded event loop optimization |
| Language      | TypeScript (strict mode)          | Type-safe domain models & configuration schemas |
| Framework     | Express.js                        | Modular controller mapping |
| Rate Limiter  | `express-rate-limit` & Redis      | Protect gateway from resource exhaustion / DOS |
| Schema Linter | `ajv`                             | Schema validation for rules and payload JSONs |
| Dev Server    | ts-node-dev                       | Local hot-reloading |
| File Upload   | Multer                            | In-memory buffers to avoid writing raw files to disk |
| Text Extraction| `pdf-parse` & `mammoth`           | Extends scope to cover unstructured documents |
| Logging       | Winston (JSON structured)         | Configured to exclude raw payloads |
| Config Sync   | Redis Pub/Sub / K8s ConfigMap     | Real-time synchronization across multiple replicas |
| MIME Detection| `mime-types`                      | Verifies content-type signatures |
| Tokenization  | `@dqbd/tiktoken` (WASM)           | High-performance native token parsing |
| Toxicity ML   | TensorFlow.js (worker thread)     | Prevent event-loop blocking by running in worker threads |
| Secrets Check | Gitleaks rule subsets + Entropy   | Dual-pattern scans with math entropy filters |
| Deployment    | Docker, Kubernetes                | Replicated deployment architecture |
| CI/CD         | GitHub Actions                    | Continuous integration & automated tests |
| Monitoring    | Prometheus + Grafana              | Tracking latency histograms per detector |
| Security      | TLS, vault-based secrets          | Keep API credentials secure |

---

## Phase 7: Sample Code & Integration
(Example: Parallel & Extensible Moderation Pipeline)

```ts
import express from 'express';
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import Redis from 'ioredis';
import Ajv from 'ajv';
import { apiKeyAuth } from './middleware/auth';
import { countTokens } from './utils/tokenizer';
import { config, reloadConfigSchema } from './config';

const app = express();
app.use(express.json());
const ajv = new Ajv();

// 1. Rate Limiting Gateway protection
const redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const limiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args: string[]) => redisClient.call(args[0], ...args.slice(1))
  }),
  windowMs: config.rateLimiter.windowMs || 60000,
  max: config.rateLimiter.maxRequests || 100,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/moderation/', limiter);

// Common interface for decoupled detector modules
interface Detector {
  name: string;
  execute(text: string): Promise<{ action: 'allow' | 'mask' | 'block'; output?: string }>;
}

// Example detectors
class PiiDetector implements Detector {
  name = 'PII';
  async execute(text: string) {
    const ssnRegex = /\d{3}-\d{2}-\d{4}/g;
    const hasPii = ssnRegex.test(text);
    return {
      action: hasPii ? config.detectors.PII.action : 'allow',
      output: text.replace(ssnRegex, config.detectors.PII.maskingStrategy)
    };
  }
}

class SecretsDetector implements Detector {
  name = 'Secrets';
  async execute(text: string) {
    const hasSecret = /AWS_SECRET_KEY=\w+/.test(text);
    return {
      action: hasSecret ? config.detectors.Secrets.action : 'allow'
    };
  }
}

// Active detectors mapped by configuration
const detectorRegistry: Record<string, Detector> = {
  PII: new PiiDetector(),
  Secrets: new SecretsDetector()
};

// 2. Chat History (Multi-Turn) & Text Moderation Controller
app.post('/moderation/text', apiKeyAuth, async (req, res) => {
  const { text, messages } = req.body;

  // Extract full textual scope (single text or combined chat history)
  let contentToScan = '';
  if (messages && Array.isArray(messages)) {
    contentToScan = messages.map((m: any) => `${m.role}: ${m.content}`).join('\n');
  } else if (text) {
    contentToScan = text;
  } else {
    return res.status(400).json({ error: 'Request body must contain text or messages' });
  }

  // Early-Reject validation (Token Check)
  if (countTokens(contentToScan) > config.tokenValidator.maxTokens) {
    return res.status(400).json({
      decision: 'block',
      reason: 'Token limit exceeded',
      detector: 'TokenValidator'
    });
  }

  const activeDetectors = config.executionOrder
    .map(name => detectorRegistry[name])
    .filter(Boolean);

  let currentText = contentToScan;

  try {
    // Parallel Execution of Independent Detectors with Fail-Safe Boundaries
    const detectorPromises = activeDetectors.map(async (detector) => {
      try {
        return await detector.execute(currentText);
      } catch (error) {
        // Retrieve detector-specific fail-safe setting
        const failOpen = config.detectors[detector.name]?.failOpen ?? false;
        if (failOpen) {
          console.warn(`Detector ${detector.name} failed. Failing open...`, error);
          return { action: 'allow' as const, output: currentText };
        }
        throw new Error(`Detector ${detector.name} failed and is configured to fail closed.`);
      }
    });

    const results = await Promise.all(detectorPromises);

    // Aggregate Decisions
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const detectorName = activeDetectors[i].name;

      if (result.action === 'block') {
        return res.json({
          decision: 'block',
          reason: `Policy violation detected by ${detectorName}`,
          detector: detectorName
        });
      }

      if (result.action === 'mask' && result.output) {
        currentText = result.output; // Apply text transformations/masking
      }
    }

    res.json({ decision: 'allow', final_output: currentText });
  } catch (error: any) {
    res.status(500).json({ decision: 'block', error: error.message });
  }
});

// 3. Dynamic Rule reloading with AJV validation
app.post('/admin/rules/reload', apiKeyAuth, async (req, res) => {
  const newRules = req.body;
  const validate = ajv.compile(reloadConfigSchema);
  const isValid = validate(newRules);

  if (!isValid) {
    return res.status(400).json({
      error: 'Invalid rules configuration schema',
      details: validate.errors
    });
  }

  // Rules are valid, apply to memory & propagate across cluster via Redis PubSub
  Object.assign(config, newRules);
  await redisClient.publish('config-reload', JSON.stringify(newRules));

  res.json({ status: 'success', message: 'Rules validated and reloaded across all nodes.' });
});
```

---

## Phase 8: Security & Compliance
*   **Authentication & Access Control:** API key authorization with role-based restrictions.
*   **Rate Limiting & Anti-Abuse:** Integrated Redis-backed rate-limiting at gateway endpoints to prevent DoS attacks.
*   **Input Schema Linting:** Automated validation of configuration files and payload formats using `ajv` schemas.
*   **Fail-Safe Engine:** Configuration boundaries that control whether detector failures block traffic (fail-closed) or pass with alerts (fail-open).
*   **Encryption standards:** TLS 1.3 in transit, AES-256 encrypted storage volumes at rest.
*   **Privacy & Data Protection (GDPR/HIPAA):** Dynamic PII/CII masking. Compliance logs store **hashes and metadata only** (e.g. tracking `client_id` and rule violation IDs) to prevent storing plain-text secrets or PII in diagnostic logs.
*   **Security Scanning:** Integrated dependency vulnerability scans in CI/CD (npm audit / Snyk).

---

## Phase 9: Deployment & CI/CD
- **Dockerfile** → lightweight Node.js image
- **Kubernetes YAML** → replicas, autoscaling, ConfigMaps, Secrets
- **CI/CD Pipeline** → build, test, security scan, deploy
- **Monitoring** → Prometheus + Grafana dashboards
- **Rollback** → Blue/Green or Canary deployments

---

## Phase 10: Future Enhancements & Scalability Roadmap
- Multi-language support
- ML-based detectors for subtle unsafe content
- Compliance dashboard + audit portal
- Streaming moderation for real-time chat
- Integration with LLM pipelines (LangChain, RAG)
- Explainability layer (“why blocked/masked”)
- AI-assisted rule authoring

---

## Summary Table

| Detector / Service | Endpoint | Action | JSON Config | Example Output |
|--------------------|-----------|---------|--------------|----------------|
| PII | `/moderation/pii` | Mask | `{"action":"mask","maskingStrategy":"[PII_MASKED]"}` | `"My SSN is [PII_MASKED]"` |
| CII | `/moderation/cii` | Mask | `{"action":"mask","maskingStrategy":"[CII_MASKED]"}` | `"Confidential project code: [CII_MASKED]"` |
| Secrets | `/moderation/secrets` | Block | `{"action":"block"}` | `"decision":"block"` |
| Toxicity | `/moderation/toxicity` | Mask/Block | `{"action":"mask","maskingStrategy":"[TOXIC_CONTENT]"}` | `"You are [TOXIC_CONTENT]!"` |
| Prompt Injection | `/moderation/prompt-injection` | Block | `{"action":"block"}` | `"decision":"block"` |
| File Validator | `/moderation/file-validator` | Reject/Allow | `{"allowedTypes":["pdf","docx"],"mimeCheck":true,"maxSizeMB":10,"policy":"reject"}` | `"decision":"block"` |
| Token Validator | `/moderation/token-validator` | Reject/Truncate | `{"maxTokens":4096,"policy":"reject"}` | `"decision":"block"` |
| Admin Service | `/admin/rules/reload` | Reload Rules | Reloads JSON configs dynamically | `"Rules reloaded successfully"` |

---

## Visual Architecture Flow (Parallelized Pipeline)

```
       [ Client Request ]
               │
               ▼
     [ API Gateway & Auth ]
               │
      ┌────────┴────────┐
      ▼ (If File Upload)▼ (If Raw Text)
[ File Validator ]      │
      │                 │
[ Text Extractor ]      │
      │                 │
      └────────┬────────┘
               ▼
      [ Token Validator ]
               │
               ▼ (Parallel Scan)
 ┌─────────────┼─────────────┬─────────────┐
 ▼             ▼             ▼             ▼
[PII Check]  [CII Check]  [Secrets]  [Toxicity]
 └─────────────┼─────────────┼─────────────┘
               ▼
     [ Prompt Injection ]
               │
               ▼
      [ Decision Engine ]
               │
      ┌────────┴────────┐
      ▼                 ▼
[ Log Stats/Metadata ]  [ Return Response ]
```
