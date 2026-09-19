const u=`---
title: "API10:2023 — Unsafe Consumption of APIs"
slug: "API10:2023"
date: "2026-09-20"
excerpt: "Treat upstream API responses as untrusted input: validate contracts, constrain transport, and prevent provider failures from crossing your trust boundary."
tags: ["owasp", "api"]
readingMinutes: 8
cover: "matrix"
---

# API10:2023 — Unsafe Consumption of APIs

> **Category:** OWASP API Security Top 10 (2023)  
> **Impact:** Depends on the exposed operation, data, and deployment.

## 🎯 What Is It?

**Unsafe Consumption of APIs** occurs when an application gives data from another API more trust than it deserves. A supplier can be compromised, return malformed data, or simply change behavior. Your service remains responsible for what it does with that response.

Transport authentication establishes which service answered. It does not establish that every returned field is safe to store, render, execute, or use in a business decision.

## 🔬 Attack Surface Map

\`\`\`text
External API → bounded HTTP client → schema validation → business validation
                                                            ↓
                                                   internal data model
                                                            ↓
                                                   safe output or storage
\`\`\`

Each stage answers a different question: was the connection allowed, was the response bounded, does the shape match, and is the value acceptable for this operation?

## 💥 Attack Scenarios

### Scenario 1: A provider changes a price field

A fictional shipping provider returns a quote with an unexpected currency or a negative amount. A consumer that copies the response directly into a checkout record can apply a nonsensical charge even though JSON parsing succeeds.

### Scenario 2: External text reaches a dangerous sink

An enrichment service returns a customer label. The consumer concatenates that label into a database query or renders it as raw HTML. The external API has become another input path for injection. Use parameterized queries and context-appropriate output encoding regardless of where a string originated.

## ❌ Vulnerable Code Example

\`\`\`javascript
async function getShippingQuote(orderId) {
  const response = await fetch(\`https://shipping.example.test/quotes/\${orderId}\`);
  return response.json(); // No deadline, size bound, or contract checks.
}
\`\`\`

A successful JSON parse does not establish HTTP success, a supported currency, an integer monetary value, or a relationship to the intended order.

## ✅ Validate the Domain Boundary

\`\`\`javascript
function validateQuote(value, expectedOrderId) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid provider response');
  }
  if (value.orderId !== expectedOrderId || value.currency !== 'USD') {
    throw new Error('Quote does not match the order');
  }
  if (!Number.isSafeInteger(value.amountCents) ||
      value.amountCents < 0 || value.amountCents > 100_000) {
    throw new Error('Quote amount outside supported bounds');
  }
  if (typeof value.quoteId !== 'string' ||
      !/^[A-Za-z0-9_-]{1,64}$/.test(value.quoteId)) {
    throw new Error('Invalid quote identifier');
  }

  // Only approved fields cross into the internal model.
  return {
    orderId: expectedOrderId,
    quoteId: value.quoteId,
    currency: 'USD',
    amountCents: value.amountCents
  };
}
\`\`\`

The ceiling and currency are example product rules, not universal security constants. Obtain \`expectedOrderId\` from an order the authenticated caller is authorized to access. For a real checkout, also enforce quote expiry and confirm that the quote belongs to the expected destination and shipping service.

## ✅ Constrain the HTTP Client

\`\`\`text
fetchQuote(authorizedOrder):
  construct URL from a fixed provider origin and encoded order identifier
  send only the provider's scoped credential
  verify TLS using the platform trust configuration
  reject unexpected redirects
  apply a deadline that covers headers and response-body reads
  require a successful status and expected media type
  stream response with a strict byte ceiling; cancel on overflow
  parse JSON and validateQuote(body, authorizedOrder.id)
  map provider failures to a controlled application error
\`\`\`

This is pseudocode for an integration client, not a complete HTTP implementation. Enforce the byte ceiling while reading, before buffering or parsing the full body. A \`Content-Length\` check alone cannot bound chunked or decompressed responses. See the bounded reader in [API7:2023](/blog/API7:2023) for a concrete example.

## 🛡️ Failure and Retry Policy

| Condition | Intended behavior |
| --- | --- |
| Invalid schema or mismatched order | Reject response and record a sanitized diagnostic |
| Deadline exceeded | Cancel work and return a controlled dependency error |
| Temporary upstream failure | Use bounded retries only where the operation is safe |
| Payment result uncertain | Reconcile using a stable operation identifier |
| Repeated provider failures | Apply a circuit breaker or bounded fallback policy |

Never convert a failed fraud or authorization check into an automatic approval merely to keep the endpoint responsive. If a fallback is needed, define which decisions it can make and how stale its data may be.

For provider callbacks, verify the provider's documented signature over the required raw bytes and enforce replay controls. The callback body is still untrusted after signature verification; validate its schema and allowed state transition.

## 🧩 More Examples and Solutions

### Example 3: Duplicate callbacks fulfill one order twice

A payment provider retries a callback after the consumer times out. Both deliveries have valid signatures. The handler credits the wallet twice because signature verification is treated as proof that an event has never been processed.

**Solution:** combine provider-specific verification with durable deduplication and a business invariant:

\`\`\`text
Illustrative callback processing:
  read the size-bounded raw request body
  verify signature and timestamp using the provider's supported verifier
  validate event schema, provider account, environment, and event type
  find the local order through a trusted provider-reference mapping
  validate amount, currency, and the permitted state transition

  begin transaction
    insert receipt with UNIQUE(providerAccount, eventId)
      if already present: acknowledge without repeating changes
    conditionally transition the order from pending to paid
    insert fulfillment outbox record with UNIQUE(orderId, action)
  commit
  acknowledge successful durable acceptance
\`\`\`

The order invariant matters even if two different event IDs describe the same payment. Dispatch fulfillment from the outbox with its own stable idempotency key. If durable acceptance fails, follow the provider's retry protocol instead of acknowledging and losing the event. These are architectural contracts; use the actual provider's signature format rather than inventing a generic one.

### Example 4: Provider text is interpolated into SQL

An address-validation service returns a normalized label. The consumer builds a SQL statement by concatenating that label. A compromised provider can now influence query syntax.

\`\`\`python
# VULNERABLE: external data becomes SQL syntax.
sql = "UPDATE addresses SET label = '" + provider_label + "' WHERE id = 7"
\`\`\`

**Solution:** validate the allowed domain value, then pass it as a bound parameter. This example uses Python sqlite3-style placeholders; other drivers have their own placeholder syntax:

\`\`\`python
def save_label(connection, actor, address_id, provider_label):
    if not isinstance(provider_label, str) or not 1 <= len(provider_label) <= 200:
        raise ValueError("Invalid provider label")
    cursor = connection.execute(
        "UPDATE addresses SET label = ? WHERE id = ? AND tenant_id = ?",
        (provider_label, address_id, actor.tenant_id),
    )
    if cursor.rowcount != 1:
        raise ValueError("Address unavailable")
\`\`\`

The caller must authorize the address update and manage the transaction. If the label is later displayed in HTML, use ordinary escaped text rendering; safe SQL storage does not make a string safe for every output context.

### Solution: Bound Retries by Outcome

For a read-only quote lookup, a small number of retries within one overall deadline may be acceptable. For a shipment creation request, a timeout can mean the provider accepted it but the response was lost. Query the operation's status or retry with the same provider-supported idempotency key before creating another shipment.

| Upstream behavior | Consumer assertion |
| --- | --- |
| Same valid event delivered twice | One durable business effect |
| Different events describe the same payment | Order cannot be fulfilled twice |
| Valid signature from the wrong provider account | No local order update |
| Label contains quote characters | Stored as data without changing query behavior |
| Provider accepts a side effect then disconnects | Reconciliation precedes another creation attempt |
| Provider sends an older state after a newer one | State machine prevents an invalid regression |

## 🧪 Testing the Boundary

Use a mock upstream to return wrong types, missing fields, a mismatched order, oversized bodies, delayed chunks, redirects, invalid JSON, and non-success statuses. Confirm that each failure produces a controlled response and no partial business update.

For side effects, simulate a connection dropping after the provider accepted the operation. Verify that a retry reconciles or deduplicates the original operation instead of creating another charge or shipment.

## 📋 Security Checklist

- [ ] Keep TLS verification enabled and constrain destinations.
- [ ] Bound connection time, body reads, response size, and retries.
- [ ] Validate structure, values, and business relationships.
- [ ] Copy only approved fields into internal models.
- [ ] Keep provider credentials separate from end-user credentials.
- [ ] Authenticate callbacks and reject replayed events.
- [ ] Test malformed responses and uncertain side effects.

## 🔗 Series Complete

Together, API1–API10 cover object, identity, property, resource, function, workflow, outbound-request, configuration, inventory, and integration boundaries. Use them as review prompts for the same request path: a single feature can cross several of these boundaries.

## 📚 References

- [OWASP API Security — API10:2023](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Stripe Webhooks: Signature Verification and Delivery Handling](https://docs.stripe.com/webhooks)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)


---`,p=`---
title: "API1:2023 — Broken Object Level Authorization (BOLA)"
slug: "API1:2023"
date: "2026-04-28"
excerpt: "Broken Object Level Authorization (BOLA) is the #1 most critical API vulnerability. It occurs when an API endpoint receives an object identifier (like a user ID, document ID, or order number) but fails to verify that the requesting user actually has permission to access that specific object."
tags: ["owasp", "api"]
readingMinutes: 12
cover: "matrix"
---


# API1:2023 — Broken Object Level Authorization (BOLA)

> **Category:** OWASP API Security Top 10  
> **Risk Level:** 🔴 Critical  
> **Previously Known As:** IDOR (Insecure Direct Object Reference) in older classifications  
> **CWE:** CWE-285 (Improper Authorization)

---

## 🎯 What Is It?

Broken Object Level Authorization (BOLA) is the **#1 most critical API vulnerability**. It occurs when an API endpoint receives an object identifier (like a user ID, document ID, or order number) but **fails to verify that the requesting user actually has permission to access that specific object**.

The API trusts the client-supplied identifier blindly, allowing attackers to enumerate IDs and access data that belongs to other users.

---

## 🔬 How It Works — Attack Flow

\`\`\`
┌─────────────────────────────────────────────────────────────────┐
│                        BOLA ATTACK FLOW                         │
└─────────────────────────────────────────────────────────────────┘

  Attacker logs in as user_id = 1042
        │
        ▼
  Makes a legitimate request:
  GET /api/v1/orders/9981   ← their own order
  ✅ 200 OK — works fine
        │
        ▼
  Attacker increments the ID:
  GET /api/v1/orders/9980   ← someone else's order!
  ✅ 200 OK — BOLA! Data leaks!
        │
        ▼
  Attacker writes a loop:
  for id in range(1, 100000):
      GET /api/v1/orders/{id}
  
  ═══════════════════════════════════
  Result: 100,000 orders exfiltrated
  ═══════════════════════════════════
\`\`\`

---

## 💥 Real-World Impact

| Scenario | Data Exposed |
|---|---|
| E-commerce API | Customer PII, order history, addresses |
| Healthcare API | Patient records, prescriptions, diagnoses |
| Banking API | Account balances, transaction history |
| HR System API | Salaries, performance reviews, SSNs |
| SaaS Platform | Competitor data, business metrics |

**Real Incidents:**
- **Venmo (2019):** Public transaction API exposed 200M+ transactions by iterating IDs
- **T-Mobile (2017):** API returned full customer data by supplying any phone number
- **Bumble (2020):** Dating app API exposed user location data via BOLA on profile endpoints

---

## ❌ Vulnerable Code Examples

### Example 1 — Express.js (Node.js)

\`\`\`javascript
// ❌ VULNERABLE: No authorization check
app.get('/api/orders/:orderId', async (req, res) => {
  const { orderId } = req.params;
  
  // Only checks if user is logged in — NOT if they OWN this order
  const order = await db.query(
    'SELECT * FROM orders WHERE id = ?',
    [orderId]  // ← Attacker controls this value!
  );
  
  if (!order) return res.status(404).json({ error: 'Not found' });
  
  // Returns ANY user's order to ANY authenticated user
  return res.json(order);
});
\`\`\`

**Why This Fails:**
- Authentication ✅ (user must be logged in)
- Authorization ❌ (no check that this order belongs to the logged-in user)

---

### Example 2 — Django REST Framework (Python)

\`\`\`python
# ❌ VULNERABLE: Generic retrieve view without ownership check
class OrderDetailView(RetrieveAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]  # ← Only checks login!
    
    # No get_queryset() override = any authenticated user gets any order
\`\`\`

---

### Example 3 — Spring Boot (Java)

\`\`\`java
// ❌ VULNERABLE
@GetMapping("/api/documents/{documentId}")
public ResponseEntity<Document> getDocument(
    @PathVariable Long documentId,
    @AuthenticationPrincipal User currentUser  // ← User is available but IGNORED
) {
    Document doc = documentRepository.findById(documentId)
        .orElseThrow(() -> new ResourceNotFoundException("Document not found"));
    
    // Never checks: doc.getOwnerId().equals(currentUser.getId())
    return ResponseEntity.ok(doc);
}
\`\`\`

---

## ✅ Secure Code Examples

### Fix 1 — Express.js (Ownership Check)

\`\`\`javascript
// ✅ SECURE: Always filter by both ID AND authenticated user
app.get('/api/orders/:orderId', authenticate, async (req, res) => {
  const { orderId } = req.params;
  const userId = req.user.id;  // From JWT/session — server-controlled
  
  const order = await db.query(
    // The WHERE clause enforces ownership at the database level
    'SELECT * FROM orders WHERE id = ? AND user_id = ?',
    [orderId, userId]  // ← Both conditions must match
  );
  
  if (!order) {
    // Don't reveal whether the order exists — just 404
    return res.status(404).json({ error: 'Order not found' });
  }
  
  return res.json(order);
});

// ✅ EVEN BETTER: Centralized authorization helper
async function getOrderForUser(orderId, userId) {
  const order = await db.query(
    'SELECT * FROM orders WHERE id = ? AND user_id = ?',
    [orderId, userId]
  );
  if (!order) throw new ForbiddenError('Access denied');
  return order;
}
\`\`\`

---

### Fix 2 — Django REST Framework

\`\`\`python
# ✅ SECURE: Override get_queryset to scope by current user
class OrderDetailView(RetrieveAPIView):
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Every query is automatically scoped to the logged-in user
        return Order.objects.filter(user=self.request.user)
    
    # Now fetching order 9980 while logged in as user 1042 returns 404
    # because the queryset doesn't include other users' orders

# ✅ ALTERNATIVE: Custom permission class
class IsOrderOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user

class OrderDetailView(RetrieveAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated, IsOrderOwner]
\`\`\`

---

### Fix 3 — Spring Boot

\`\`\`java
// ✅ SECURE: Pass authenticated user to service layer
@GetMapping("/api/documents/{documentId}")
public ResponseEntity<Document> getDocument(
    @PathVariable Long documentId,
    @AuthenticationPrincipal User currentUser
) {
    // Service layer enforces authorization
    Document doc = documentService.getDocumentForUser(documentId, currentUser.getId());
    return ResponseEntity.ok(doc);
}

// In DocumentService:
public Document getDocumentForUser(Long documentId, Long userId) {
    return documentRepository
        .findByIdAndOwnerId(documentId, userId)  // ← Both conditions
        .orElseThrow(() -> new AccessDeniedException("Document not found or access denied"));
}

// In DocumentRepository:
public interface DocumentRepository extends JpaRepository<Document, Long> {
    Optional<Document> findByIdAndOwnerId(Long id, Long ownerId);
}
\`\`\`

---

## 🛡️ Defense Strategies

### Strategy 1: Object-Level Authorization at Every Layer

\`\`\`
┌─────────────────────────────────────────────────────┐
│               DEFENSE IN DEPTH                      │
├─────────────────────────────────────────────────────┤
│  Layer 1: API Gateway                               │
│    → Rate limit object ID enumeration               │
│    → Require authentication token                   │
├─────────────────────────────────────────────────────┤
│  Layer 2: Controller/Handler                        │
│    → Extract user identity from token               │
│    → Pass to service layer — never trust client     │
├─────────────────────────────────────────────────────┤
│  Layer 3: Service / Business Logic                  │
│    → Authorization policy enforcement               │
│    → Role/relationship check                        │
├─────────────────────────────────────────────────────┤
│  Layer 4: Database Query                            │
│    → WHERE clause includes user_id / owner_id       │
│    → Principle of least privilege on DB user        │
└─────────────────────────────────────────────────────┘
\`\`\`

### Strategy 2: Use Non-Sequential, Non-Guessable IDs

\`\`\`javascript
// ❌ AVOID: Sequential integers (easily enumerable)
{ "orderId": 9981 }   → attacker tries 9980, 9979...

// ✅ USE: UUIDs (still need auth check, but much harder to guess)
{ "orderId": "7f3d4e2a-9b1c-4f8e-a2d7-3c6b9f1e4a5d" }

// ✅ EVEN BETTER: Combine UUID + ownership check
// UUIDs reduce attack surface; auth checks prevent exploitation

// Generating UUID in Node.js:
const { v4: uuidv4 } = require('uuid');
const orderId = uuidv4(); // "7f3d4e2a-9b1c-4f8e-a2d7-3c6b9f1e4a5d"

// Generating UUID in Python:
import uuid
order_id = str(uuid.uuid4())

// Generating UUID in Java:
UUID orderId = UUID.randomUUID();
\`\`\`

### Strategy 3: Centralized Authorization Framework

\`\`\`javascript
// ✅ Policy-based authorization (using CASL.js for Node.js)
const { AbilityBuilder, createMongoAbility } = require('@casl/ability');

function defineAbilitiesFor(user) {
  const { can, cannot, build } = new AbilityBuilder(createMongoAbility);
  
  if (user.role === 'admin') {
    can('read', 'Order');  // Admins can read all orders
  } else {
    can('read', 'Order', { userId: user.id });  // Users only see their orders
    cannot('read', 'Order', { userId: { $ne: user.id } });
  }
  
  return build();
}

// In your route handler:
app.get('/api/orders/:orderId', authenticate, async (req, res) => {
  const order = await Order.findById(req.params.orderId);
  
  if (!req.ability.can('read', order)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  return res.json(order);
});
\`\`\`

---

## 🔍 Testing for BOLA

### Manual Testing Checklist

\`\`\`
1. Log in as User A, perform an action that creates a resource
2. Note the resource ID in the response
3. Log out, log in as User B
4. Attempt to access/modify/delete that resource using User A's ID
5. If successful → BOLA vulnerability confirmed

Testing checklist:
□ GET    /api/resource/{id}           ← Read another user's resource
□ PUT    /api/resource/{id}           ← Modify another user's resource  
□ DELETE /api/resource/{id}           ← Delete another user's resource
□ POST   /api/resource/{id}/action    ← Perform action on another's resource
□ PATCH  /api/resource/{id}           ← Partial update another's resource
\`\`\`

### Automated Testing with Python

\`\`\`python
import requests

BASE_URL = "https://api.example.com"

def test_bola(user_a_token, user_b_token, resource_id):
    """
    Test if User B can access User A's resource.
    """
    headers_b = {"Authorization": f"Bearer {user_b_token}"}
    
    # User B tries to access User A's resource
    response = requests.get(
        f"{BASE_URL}/api/orders/{resource_id}",
        headers=headers_b
    )
    
    if response.status_code == 200:
        print(f"🚨 BOLA CONFIRMED: User B accessed resource {resource_id}")
        print(f"   Exposed data: {response.json()}")
        return True
    elif response.status_code in [403, 404]:
        print(f"✅ SECURE: Got {response.status_code} — access denied")
        return False
    else:
        print(f"⚠️  Unexpected status: {response.status_code}")
        return None

# Run the test
test_bola(
    user_a_token="eyJhbGc...",
    user_b_token="eyJhbGc...",
    resource_id="9981"
)
\`\`\`

---

## 📊 BOLA vs BFLA — Key Distinction

\`\`\`
┌──────────────────────────────────────────────────────────────┐
│   BOLA (API1)              │   BFLA (API5)                   │
│   Object-Level             │   Function-Level                │
├────────────────────────────┼─────────────────────────────────┤
│ "Can I access THIS         │ "Can I access THIS              │
│  specific record?"         │  endpoint/action at all?"       │
│                            │                                 │
│ GET /orders/9980           │ DELETE /admin/users/all         │
│ (other user's order)       │ (admin function as regular user)│
│                            │                                 │
│ Fix: Filter by owner_id    │ Fix: Role-based access control  │
└──────────────────────────────────────────────────────────────┘
\`\`\`

---

## 📋 Security Checklist

\`\`\`
Authorization Checks
  □ Every API endpoint performs object-level authorization
  □ Authorization uses server-side identity — never client-supplied user IDs
  □ Database queries include ownership conditions (WHERE user_id = ?)
  □ Authorization logic is centralized, not copy-pasted across endpoints

ID Design
  □ Resources use non-sequential identifiers (UUIDs preferred)
  □ IDs in URLs cannot be easily guessed or enumerated

Error Handling
  □ Return 403/404 for unauthorized access — never leak existence info
  □ Log unauthorized access attempts for monitoring

Testing
  □ Authorization tests are part of the CI/CD pipeline
  □ Cross-user access tests exist for every resource endpoint
  □ Penetration tests include BOLA/IDOR scenarios
\`\`\`

---

## 📚 References

- [OWASP API Security Top 10 — API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Testing Guide — Testing for IDOR](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [PortSwigger — IDOR Lab](https://portswigger.net/web-security/access-control/idor)

---`,h=`---
title: "API2:2023 — Broken Authentication"
slug: "API2:2023"
date: "2026-04-28"
excerpt: "Broken Authentication encompasses all weaknesses in how an API verifies who is making a request. Unlike web apps where broken auth often means weak login pages, APIs have unique authentication patterns — JWT tokens, API keys, OAuth flows — each with its own failure modes."
tags: ["owasp", "api"]
readingMinutes: 12
cover: "matrix"
---

# API2:2023 — Broken Authentication

> **Category:** OWASP API Security Top 10  
> **Risk Level:** 🔴 Critical  
> **CWE:** CWE-287 (Improper Authentication), CWE-798 (Hard-coded Credentials)

---

## 🎯 What Is It?

Broken Authentication encompasses **all weaknesses in how an API verifies who is making a request**. Unlike web apps where broken auth often means weak login pages, APIs have unique authentication patterns — JWT tokens, API keys, OAuth flows — each with its own failure modes.

An attacker who can bypass authentication gains **complete access** as the compromised user, including all their data and permissions.

---

## 🔬 Attack Surface Map

\`\`\`
┌─────────────────────────────────────────────────────────────────────┐
│                    API AUTHENTICATION ATTACK SURFACE                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Token Issues          Credential Issues      Implementation        │
│  ─────────────         ─────────────────      ──────────────        │
│  • Weak JWT secret     • No brute force        • Auth bypass        │
│  • alg=none attack       protection            • Missing auth       │
│  • Token not           • Default passwords       on endpoints       │
│    invalidated         • Credential             • Insecure          │
│  • Infinite expiry       stuffing                password reset     │
│  • Predictable         • Weak password          • Exposed API keys  │
│    tokens               policy                 • OAuth misconfig    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
\`\`\`

---

## 💥 Attack Scenarios

### Attack 1: JWT Algorithm Confusion (alg=none)

\`\`\`
Normal JWT flow:
  Header:  { "alg": "HS256", "typ": "JWT" }
  Payload: { "userId": 1042, "role": "user" }
  Signature: HMACSHA256(base64(header)+"."+base64(payload), secret)

Attacker modifies:
  Header:  { "alg": "none", "typ": "JWT" }    ← Changed!
  Payload: { "userId": 1, "role": "admin" }   ← Escalated!
  Signature: (empty)                           ← Removed!

Vulnerable servers accepting alg=none → Complete compromise
\`\`\`

### Attack 2: Credential Stuffing

\`\`\`
1. Attacker buys breached credential list from dark web
   (e.g., 500M email/password pairs from previous breaches)

2. Script tests credentials against your API:
   POST /api/auth/login
   { "email": "john@example.com", "password": "Password123" }

3. No rate limiting → 10,000 attempts/minute

4. ~1-3% success rate = thousands of compromised accounts

Timeline: 500M credentials tested in ~1 hour with distributed attack
\`\`\`

---

## ❌ Vulnerable Code Examples

### Vulnerability 1: JWT alg=none / Weak Verification

\`\`\`javascript
// ❌ VULNERABLE: Accepts any algorithm including "none"
const jwt = require('jsonwebtoken');

function verifyToken_VULNERABLE(token) {
  // jwt.decode() does NOT verify signature!
  const decoded = jwt.decode(token);  // ← Zero verification!
  return decoded;
}

// ❌ ALSO VULNERABLE: Doesn't enforce algorithm
function verifyToken_ALSO_VULNERABLE(token) {
  try {
    // If attacker sets alg=RS256, library switches to public-key mode
    // Attacker can use the PUBLIC key to sign tokens!
    return jwt.verify(token, process.env.JWT_SECRET);
    // No \`algorithms\` option specified → accepts any alg
  } catch (err) {
    return null;
  }
}

// ❌ HARDCODED SECRET: Terrible practice
const JWT_SECRET = "secret123";  // Committed to git — everyone knows it
\`\`\`

---

### Vulnerability 2: No Brute Force Protection

\`\`\`python
# ❌ VULNERABLE: Login endpoint with no rate limiting
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if user and user.check_password(password):
        token = generate_token(user)
        return jsonify({'token': token})
    
    # ❌ No rate limiting
    # ❌ No account lockout
    # ❌ No CAPTCHA
    # ❌ No failed attempt logging
    # ❌ Consistent response time (allows user enumeration)
    return jsonify({'error': 'Invalid credentials'}), 401
\`\`\`

---

### Vulnerability 3: Token Not Invalidated on Logout

\`\`\`javascript
// ❌ VULNERABLE: Logout does nothing server-side
app.post('/api/auth/logout', authenticate, (req, res) => {
  // Just tells client to delete token — server has no memory of revocation
  // Stolen token still works until it naturally expires (could be months!)
  res.json({ message: 'Logged out successfully' });
});

// ❌ VULNERABLE: Long-lived tokens with no refresh mechanism
const token = jwt.sign(
  { userId: user.id },
  process.env.JWT_SECRET,
  { expiresIn: '365d' }  // ← 1 year! If stolen, attacker has a year
);
\`\`\`

---

### Vulnerability 4: Insecure Password Reset

\`\`\`python
# ❌ VULNERABLE: Predictable reset tokens
import time
import hashlib

def generate_reset_token_VULNERABLE(user_email):
    # Using timestamp + email = predictable!
    token = hashlib.md5(f"{user_email}{time.time()}".encode()).hexdigest()
    return token

# ❌ VULNERABLE: Token never expires
def reset_password(token, new_password):
    user = User.query.filter_by(reset_token=token).first()
    if user:  # No expiry check!
        user.password = hash_password(new_password)
        # ❌ Token not invalidated after use → can be reused!
        db.session.commit()
\`\`\`

---

## ✅ Secure Code Examples

### Fix 1: Proper JWT Verification

\`\`\`javascript
// ✅ SECURE: Strict JWT verification
const jwt = require('jsonwebtoken');

const JWT_CONFIG = {
  secret: process.env.JWT_SECRET,  // Must be strong, from env
  accessTokenExpiry: '15m',        // Short-lived access tokens
  refreshTokenExpiry: '7d',        // Longer refresh tokens
  algorithm: 'HS256'               // Explicitly declared
};

function verifyAccessToken(token) {
  try {
    return jwt.verify(token, JWT_CONFIG.secret, {
      algorithms: ['HS256'],    // ✅ Whitelist ONLY expected algorithm
      issuer: 'myapp.com',      // ✅ Validate issuer
      audience: 'myapp-client'  // ✅ Validate audience
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new UnauthorizedError('Token expired');
    }
    throw new UnauthorizedError('Invalid token');
  }
}

// ✅ Access token + Refresh token pattern
async function login(email, password) {
  const user = await authenticateUser(email, password);
  
  const accessToken = jwt.sign(
    { userId: user.id, role: user.role },
    JWT_CONFIG.secret,
    { 
      expiresIn: JWT_CONFIG.accessTokenExpiry,
      algorithm: JWT_CONFIG.algorithm,
      issuer: 'myapp.com',
      audience: 'myapp-client'
    }
  );
  
  // Refresh token stored in DB with expiry
  const refreshToken = crypto.randomBytes(64).toString('hex');
  await storeRefreshToken(user.id, refreshToken, '7d');
  
  return { accessToken, refreshToken };
}
\`\`\`

---

### Fix 2: Rate Limiting + Account Lockout

\`\`\`python
# ✅ SECURE: Rate limiting + lockout + timing attack prevention
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import secrets

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes in seconds

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")  # ✅ Rate limit per IP
def login():
    data = request.get_json()
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    
    # ✅ Constant-time user lookup (prevent timing attacks)
    start_time = time.time()
    
    user = User.query.filter_by(email=email).first()
    
    # ✅ Check lockout BEFORE processing
    if user and is_account_locked(user):
        # ✅ Add delay even for locked accounts
        _constant_time_delay(start_time)
        return jsonify({'error': 'Account temporarily locked'}), 429
    
    # ✅ Use constant-time comparison
    if user and check_password_hash(user.password_hash, password):
        reset_failed_attempts(user)
        token = generate_tokens(user)
        _constant_time_delay(start_time)
        return jsonify(token)
    else:
        if user:
            record_failed_attempt(user)
        
        # ✅ Same error for wrong email OR wrong password (prevent enumeration)
        _constant_time_delay(start_time)
        return jsonify({'error': 'Invalid credentials'}), 401

def _constant_time_delay(start_time, min_duration=0.3):
    """Ensure response takes at least min_duration seconds to prevent timing attacks."""
    elapsed = time.time() - start_time
    if elapsed < min_duration:
        time.sleep(min_duration - elapsed)

def is_account_locked(user):
    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        lockout_until = user.last_failed_login + LOCKOUT_DURATION
        if time.time() < lockout_until:
            return True
        else:
            reset_failed_attempts(user)
    return False
\`\`\`

---

### Fix 3: Token Revocation (Blacklist Pattern)

\`\`\`javascript
// ✅ SECURE: Token revocation on logout using Redis blacklist
const redis = require('redis');
const client = redis.createClient();

async function logout(req, res) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (token) {
    const decoded = jwt.decode(token);
    const remainingTTL = decoded.exp - Math.floor(Date.now() / 1000);
    
    if (remainingTTL > 0) {
      // ✅ Blacklist the token until it would have naturally expired
      await client.setEx(\`blacklist:\${token}\`, remainingTTL, 'revoked');
    }
  }
  
  res.json({ message: 'Logged out successfully' });
}

// ✅ Check blacklist in middleware
async function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Token required' });
  
  // ✅ Check if token has been revoked
  const isRevoked = await client.get(\`blacklist:\${token}\`);
  if (isRevoked) {
    return res.status(401).json({ error: 'Token has been revoked' });
  }
  
  try {
    req.user = verifyAccessToken(token);
    next();
  } catch (err) {
    return res.status(401).json({ error: err.message });
  }
}
\`\`\`

---

### Fix 4: Secure Password Reset

\`\`\`python
# ✅ SECURE: Cryptographically random, time-limited, single-use tokens
import secrets
import hashlib
from datetime import datetime, timedelta

def generate_reset_token(user_id):
    # ✅ Cryptographically secure random token
    raw_token = secrets.token_urlsafe(32)  # 256-bit entropy
    
    # ✅ Store hashed version (so DB breach doesn't expose tokens)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    
    expiry = datetime.utcnow() + timedelta(hours=1)  # ✅ 1 hour expiry
    
    PasswordResetToken.create(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expiry,
        used=False  # ✅ Track single-use
    )
    
    return raw_token  # Return raw token to send via email

def reset_password(raw_token, new_password):
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    
    reset_record = PasswordResetToken.query.filter_by(
        token_hash=token_hash,
        used=False  # ✅ Must not have been used
    ).first()
    
    if not reset_record:
        raise ValueError("Invalid or already-used reset token")
    
    # ✅ Check expiry
    if datetime.utcnow() > reset_record.expires_at:
        raise ValueError("Reset token has expired")
    
    # ✅ Mark as used BEFORE changing password (prevent race condition)
    reset_record.used = True
    db.session.commit()
    
    user = User.query.get(reset_record.user_id)
    user.password_hash = generate_password_hash(new_password)
    
    # ✅ Invalidate all existing sessions
    invalidate_all_user_sessions(user.id)
    
    db.session.commit()
\`\`\`

---

## 🔐 API Key Best Practices

\`\`\`python
# ✅ Generating secure API keys
import secrets
import hashlib

def generate_api_key():
    # Format: prefix + random bytes for easy identification
    prefix = "sk_live"  # "sk_" = secret key, "live" = environment
    raw = secrets.token_urlsafe(32)
    api_key = f"{prefix}_{raw}"
    
    # Store ONLY the hash in the database
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    ApiKey.create(
        key_hash=key_hash,
        prefix=api_key[:12],  # Store prefix for UI display "sk_live_xxxx..."
        created_at=datetime.utcnow(),
        last_used_at=None,
        scopes=['read'],
        is_active=True
    )
    
    # Return the full key ONCE — never shown again (like GitHub tokens)
    return api_key

# ✅ Validating API keys
def authenticate_api_key(raw_key):
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    api_key = ApiKey.query.filter_by(
        key_hash=key_hash,
        is_active=True
    ).first()
    
    if not api_key:
        raise UnauthorizedError("Invalid API key")
    
    # Update last used timestamp
    api_key.last_used_at = datetime.utcnow()
    db.session.commit()
    
    return api_key
\`\`\`

---

## 📋 Security Checklist

\`\`\`
JWT Security
  □ Algorithms whitelist specified (never accept alg=none)
  □ Secret is minimum 256-bit, stored in environment variables
  □ Access tokens expire in ≤15 minutes
  □ Token revocation mechanism implemented (blacklist/allowlist)
  □ Issuer and audience claims validated

Credential Security  
  □ Rate limiting on all authentication endpoints
  □ Account lockout after N failed attempts
  □ Constant-time password comparison
  □ Same error message for wrong email and wrong password
  □ Password reset tokens: cryptographic, single-use, time-limited

API Key Security
  □ Keys stored as hashes — never plaintext
  □ Keys scoped to minimum required permissions
  □ Keys can be revoked individually
  □ Key usage logged and monitored

General
  □ MFA available/enforced for sensitive accounts
  □ No credentials hardcoded or committed to version control
  □ Authentication errors logged (not to client)
\`\`\`

---

## 📚 References

- [OWASP API Security — API2:2023](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [JWT Security Best Practices](https://curity.io/resources/learn/jwt-best-practices/)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

---`,m=`---
title: "API3:2023 — Broken Object Property Level Authorization"
slug: "API3:2023"
date: "2026-09-20"
excerpt: "Protect individual fields as carefully as objects: prevent excessive data exposure and mass assignment with explicit read and write policies."
tags: ["owasp", "api"]
readingMinutes: 7
cover: "matrix"
---

# API3:2023 — Broken Object Property Level Authorization

> **Category:** OWASP API Security Top 10 (2023)  
> **Impact:** Depends on the exposed operation, data, and deployment.

## 🎯 What Is It?

A user may be allowed to access a record without being allowed to read or change every field on that record. **Broken Object Property Level Authorization** happens when the API misses that distinction. The 2023 category brings together excessive data exposure and mass assignment from the 2019 list.

A profile owner can edit their display name. That does not grant permission to change their account role, verification state, or billing credit. Similarly, another user's public profile should not include private recovery information. These field decisions belong on the server.

## 🔬 Attack Surface Map

\`\`\`text
Request JSON → input field policy → object authorization → database
Database     → output field policy → response JSON       → client
                 ↑ enforce both directions
\`\`\`

| Surface | Example mistake | Consequence |
| --- | --- | --- |
| Profile update | Request body copied into database model | Role or account state changed |
| Customer response | Entire database row serialized | Internal notes disclosed |
| GraphQL resolver | Sensitive fields inherit parent access | Private attributes queried |
| Nested update | Top-level fields checked, child fields unchecked | Protected relationship changed |

## 💥 Attack Scenarios

### Scenario 1: A profile update changes account privileges

In a fictional training application, a member submits their normal profile change plus a field the interface never shows:

\`\`\`http
PATCH /api/me
Content-Type: application/json
Authorization: Bearer <lab-member-token>

{"displayName":"Sam","role":"admin"}
\`\`\`

If the handler blindly copies the body into the user model, the extra field becomes an authorization bypass. Hiding the role selector in the browser does not constrain an HTTP client.

### Scenario 2: A support view reveals billing notes

A support dashboard only displays a customer's name. The endpoint returns the whole customer row, including billing notes and recovery codes. Anyone allowed to call that endpoint can inspect the response regardless of what the dashboard renders.

## ❌ Vulnerable Code Example

\`\`\`javascript
// Illustrative Express-style handler; authentication runs first.
app.patch('/api/me', authenticate, async (req, res) => {
  const user = await users.update(req.user.id, req.body);
  res.json(user); // Both unrestricted input and unrestricted output.
});
\`\`\`

Two independent problems exist: clients choose database fields, and the response exposes fields without a read policy. Fixing only one leaves the other open.

## ✅ Safer Code Example

\`\`\`javascript
// users and authenticate are application-provided dependencies.
app.patch('/api/me', authenticate, async (req, res) => {
  const body = req.body;
  if (!body || Array.isArray(body) || typeof body !== 'object') {
    return res.status(400).json({ error: 'Expected an object' });
  }

  const allowed = new Set(['displayName']);
  if (Object.keys(body).some(key => !allowed.has(key))) {
    return res.status(400).json({ error: 'Unsupported field' });
  }
  if (typeof body.displayName !== 'string' ||
      body.displayName.trim().length < 1 ||
      body.displayName.length > 80) {
    return res.status(400).json({ error: 'Invalid display name' });
  }

  const user = await users.update(req.user.id, {
    displayName: body.displayName.trim()
  });
  res.json({ id: user.id, displayName: user.displayName });
});
\`\`\`

The authenticated identity selects the record. An explicit input model restricts writes, while an explicit response model restricts reads. A production application also needs centralized error handling and equivalent policies on every alternate update path.

For an administrator endpoint, define its permitted fields separately and check the administrator's authority before applying them. Do not expand this public profile schema simply because an administrator client needs more fields.

## 🧩 More Examples and Solutions

### Example 3: GraphQL exposes a private field

A member can read another member's public profile. Adding \`recoveryEmail\` to the selection set also works because the schema's default resolver returns any matching model property.

\`\`\`graphql
query {
  member(id: "lab-member-2") {
    displayName
    recoveryEmail
  }
}
\`\`\`

**Solution:** authorize the sensitive field independently. The following resolver sketch assumes the parent resolver already authorizes access to the member object:

\`\`\`javascript
const resolvers = {
  Member: {
    recoveryEmail: async (member, args, context) => {
      await context.policy.require(context.actor, 'member:read-recovery-email', {
        tenantId: member.tenantId,
        memberId: member.id
      });
      return member.recoveryEmail;
    }
  }
};
\`\`\`

Keep the field nullable if the intended behavior permits partial responses with a field error. GraphQL errors can coexist with HTTP \`200\`, so tests must inspect \`data\` and \`errors\`. Also scope loaders and caches to the request or permission context; a cached privileged response must not be reused for another caller.

### Example 4: Nested address updates overwrite verification

A checkout API allows customers to edit their delivery address. A generic deep merge also accepts \`address.verified\`, allowing the client to mark an unverified address as trusted.

\`\`\`json
{
  "address": {
    "line1": "42 Training Lane",
    "postalCode": "12345",
    "verified": true
  }
}
\`\`\`

**Solution:** validate every level and build a fresh update object. This illustrative Python helper handles a deliberately small address model:

\`\`\`python
def address_update(body):
    if not isinstance(body, dict) or set(body) != {"address"}:
        raise ValueError("Expected address only")
    address = body["address"]
    allowed = {"line1", "postalCode"}
    if not isinstance(address, dict) or set(address) != allowed:
        raise ValueError("Unsupported address fields")
    for key, maximum in (("line1", 120), ("postalCode", 20)):
        value = address[key]
        if not isinstance(value, str) or not 1 <= len(value.strip()) <= maximum:
            raise ValueError("Invalid address")
    return {
        "line1": address["line1"].strip(),
        "postalCode": address["postalCode"].strip(),
        "verified": False,  # An address change invalidates prior verification.
    }
\`\`\`

Apply this update only to an authorized address record. A separate verification service owns the transition back to \`verified: true\`; input validation alone cannot establish that the address is deliverable.

### Regression Cases for Property Policies

| Input or action | Expected result |
| --- | --- |
| Public profile asks for recovery email | Sensitive field denied or omitted under the defined contract |
| Owner requests their recovery email | Allowed only by explicit field policy |
| Address contains \`verified\` | Rejected with no database change |
| Address changes legitimately | New address saved and old verification invalidated |
| A database migration adds a sensitive column | Existing public response keys remain unchanged |

## 🧪 Testing the Boundary

Using fixture accounts in a local or authorized test environment:

1. Save a permitted display name and verify that it persists.
2. Add \`role\`, \`verified\`, or \`creditBalance\` individually; expect rejection and unchanged database values.
3. Try protected fields inside nested objects and arrays.
4. Check responses from list, detail, export, and GraphQL operations for private properties.
5. Repeat with each role; validate the exact response keys as well as status codes.

A successful response containing no forbidden field does not prove the update was safe. Check stored state too: some handlers silently update fields that they never return.

## 📋 Security Checklist

- [ ] Define readable and writable fields for each operation and role.
- [ ] Validate nested input and reject unexpected properties.
- [ ] Construct response objects explicitly instead of serializing models.
- [ ] Keep server-owned properties out of client update models.
- [ ] Test persistence and response shapes with low-privilege accounts.

## 🔗 Related Risks

[API1:2023](/blog/API1:2023) asks whether the caller can access the object. API3 asks which properties they can access. [API5:2023](/blog/API5:2023) asks whether they can invoke the operation at all.

## 📚 References

- [OWASP API Security — API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)


---`,f=`---
title: "API4:2023 — Unrestricted Resource Consumption"
slug: "API4:2023"
date: "2026-09-20"
excerpt: "Bound the work behind each API request: control payload size, query cost, concurrency, and paid integrations before they exhaust resources."
tags: ["owasp", "api"]
readingMinutes: 7
cover: "matrix"
---

# API4:2023 — Unrestricted Resource Consumption

> **Category:** OWASP API Security Top 10 (2023)  
> **Impact:** Depends on the exposed operation, data, and deployment.

## 🎯 What Is It?

**Unrestricted Resource Consumption** occurs when requests can spend more compute, memory, storage, bandwidth, or external-service budget than intended. A valid authenticated request can still be too expensive to serve.

Request frequency is only one dimension. One request might trigger thousands of database queries, generate a large export, or start many paid operations. Defenses must bound both the number of requests and the work each request creates.

## 🔬 Attack Surface Map

\`\`\`text
Incoming request
  ├─ body size / decompressed size
  ├─ page size / batch count / query complexity
  ├─ execution time / concurrent jobs
  └─ downstream calls / storage / financial cost
\`\`\`

## 💥 Attack Scenarios

### Scenario 1: A small request creates a huge export

A fictional analytics endpoint accepts any \`limit\` and loads all matching records into memory before building a spreadsheet. A single request for an oversized page can exhaust the worker even when the caller stays below the request-rate limit.

### Scenario 2: Retries multiply paid work

A document-processing endpoint starts a paid OCR job whenever it receives a request. A client times out and retries, creating multiple jobs for the same document. Without deduplication and a tenant budget, accidental retries and deliberate repetition have the same financial effect.

## ❌ Vulnerable Code Example

\`\`\`javascript
app.get('/api/events', authenticate, async (req, res) => {
  const rows = await events.list({
    tenantId: req.user.tenantId,
    limit: Number(req.query.limit) || 1000
  });
  res.json(rows);
});
\`\`\`

An unrestricted page size lets the caller choose the amount of database and serialization work. A fallback value is not a maximum.

## ✅ Safer Code Example

\`\`\`javascript
// authenticate, tenantRateLimit, and events are application dependencies.
// tenantRateLimit uses an atomic shared store across API instances.
app.get('/api/events', authenticate, tenantRateLimit, async (req, res) => {
  const rawLimit = req.query.limit ?? '50';
  if (typeof rawLimit !== 'string' || !/^[1-9][0-9]{0,2}$/.test(rawLimit)) {
    return res.status(400).json({ error: 'Invalid limit' });
  }
  const limit = Number(rawLimit);
  if (limit > 100) {
    return res.status(400).json({ error: 'Maximum limit is 100' });
  }

  const rows = await events.list({
    tenantId: req.user.tenantId,
    limit
  });
  res.json({ items: rows });
});
\`\`\`

This example bounds page size; it is not a complete resource-control system. The repository must apply the limit in the database query, use appropriate indexes, and enforce a database statement timeout. Rejecting a large result after loading it is too late. Add bounded cursor pagination when clients need subsequent pages.

## 🛡️ Layered Limits

| Layer | Control | Why it matters |
| --- | --- | --- |
| Gateway | Body size, connection and request deadlines | Reject work before allocating application resources |
| Application | Per-account and tenant quotas | Keep one customer from exhausting shared capacity |
| Query | Page limits, batch caps, complexity budgets | Bound work within a single request |
| Worker | Queue depth and concurrency limits | Prevent unbounded background accumulation |
| Integration | Deduplication and spend ceilings | Bound repeated billable operations |
| Runtime | Memory and CPU ceilings | Contain the effect of a failing worker |

Use a shared atomic quota store when several application instances serve the same tenant. A separate in-memory counter on every instance multiplies the effective allowance. Decide how the system behaves if that store is unavailable; expensive operations should not silently become unlimited.

A timeout must cancel downstream work where supported. Merely stopping the HTTP response can leave a database query or worker running. Billing alerts help operators detect a problem but do not enforce a spending cap.

## 🧩 More Examples and Solutions

### Example 3: GraphQL aliases multiply expensive work

A report query is allowed once per request, but aliases let a single document call it several times:

\`\`\`graphql
query {
  first: monthlyReport(month: "2026-01") { total }
  second: monthlyReport(month: "2026-02") { total }
  third: monthlyReport(month: "2026-03") { total }
}
\`\`\`

**Solution:** calculate cost over the validated operation, including aliases, expanded fragments, variable-dependent list sizes, and batched operations. A depth limit alone will miss three shallow but expensive reports.

\`\`\`text
Illustrative admission policy:
  reject oversized GraphQL documents before parsing
  parse and validate using the GraphQL implementation
  select the requested operation and resolve its variable bounds
  calculate total field cost, including multiplicative list sizes
  reject if cost exceeds the per-operation budget
  atomically reserve cost units from the tenant's shared budget
  execute with a deadline and bounded database work
\`\`\`

The cost function should reflect observed work. A field that fans out to a paid provider needs a different weight from a cached scalar. Apply a separate batch cap so many acceptable operations cannot bypass the overall budget.

### Example 4: An archive expands beyond the upload limit

An import service accepts a small compressed archive, then extracts every entry to disk. The compressed upload passes the gateway limit while the extracted data exhausts temporary storage.

**Solution:** cap entry count, per-entry output, total output, and extraction duration. Enforce output limits as bytes are produced, rather than trusting archive metadata.

\`\`\`python
# Illustrative streaming helper; run within an isolated import worker.
def copy_entry(source, target, remaining_total):
    entry_bytes = 0
    while True:
        chunk = source.read(64 * 1024)
        if not chunk:
            return remaining_total
        entry_bytes += len(chunk)
        remaining_total -= len(chunk)
        if entry_bytes > 5 * 1024 * 1024 or remaining_total < 0:
            raise ValueError("Extraction budget exceeded")
        target.write(chunk)
\`\`\`

The archive controller must carry \`remaining_total\` across entries, stop on failure, and remove partial output. Reject unsafe paths, symbolic links, and unsupported entry types before creating files; byte limits do not prevent archive path traversal. Also bound nested archives and use process-level memory, CPU, and disk quotas because decoding itself consumes resources.

### Choosing Limits and Verifying Them

Start with the smallest limits that support measured legitimate workloads, then monitor rejection rates before raising them. Document whether a quota measures requests, records, bytes, or money; these units are not interchangeable.

| Test fixture | Expected result |
| --- | --- |
| Shallow query with many expensive aliases | Cost rejection before resolvers run |
| Several operations in one batch | Aggregate cost charged to one budget |
| Archive exceeding output allowance | Extraction stops and partial files disappear |
| Import worker crashes | Lease expires or is recovered; queue capacity remains bounded |
| Rate-limit store unavailable | Explicit degraded policy; no accidental unlimited access |

## 🧪 Testing the Boundary

Use small configured limits in a test environment instead of generating production load:

1. Test page limits at 1, the maximum, and one above it.
2. Submit negative, fractional, repeated, and nonnumeric query parameters.
3. Verify that an oversized body is rejected before expensive processing.
4. Send a bounded batch and confirm that quotas count its operations.
5. Simulate downstream timeouts and ensure retries do not duplicate paid jobs.
6. Check that one tenant hitting a quota leaves another tenant usable.

## 📋 Security Checklist

- [ ] Bound payloads, arrays, uploads, and decompressed content.
- [ ] Apply timeouts and cancellation through downstream calls.
- [ ] Limit batch complexity and background concurrency.
- [ ] Use shared quotas with intentional failure behavior.
- [ ] Track latency, queue depth, rejected work, and integration spend.
- [ ] Return \`429\` for rate limits, with retry guidance where appropriate.

## 🔗 Related Risks

[API6:2023](/blog/API6:2023) addresses abuse of business outcomes. An API can remain fast and inexpensive while automated purchases still harm customers.

## 📚 References

- [OWASP API Security — API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)


---`,y=`---
title: "API5:2023 — Broken Function Level Authorization"
slug: "API5:2023"
date: "2026-09-20"
excerpt: "Enforce permission checks on every operation so ordinary accounts cannot invoke administrative or privileged API functions."
tags: ["owasp", "api"]
readingMinutes: 7
cover: "matrix"
---

# API5:2023 — Broken Function Level Authorization

> **Category:** OWASP API Security Top 10 (2023)  
> **Impact:** Depends on the exposed operation, data, and deployment.

## 🎯 What Is It?

**Broken Function Level Authorization (BFLA)** means the server allows a caller to perform an operation outside their permissions. Authentication establishes identity; it does not establish permission to issue refunds, invite administrators, or delete accounts.

Permissions must cover each route and method, including background operations and alternative API versions. An administrative-looking URL does not protect a function, and a normal-looking URL may still expose an administrative action.

## 🔬 Attack Surface Map

| Operation | Expected caller | Common missing check |
| --- | --- | --- |
| Create staff invitation | Organization administrator | Only checks login |
| Approve refund | Authorized finance operator | Trusts a client role field |
| Delete customer | Tenant administrator | Checks role but not tenant |
| Bulk export | Explicit export permission | Reuses ordinary list access |

## 💥 Attack Scenarios

### Scenario 1: A hidden invitation endpoint

A training application hides its staff invitation screen from regular members. The server still accepts their requests to the invitation endpoint. A member can therefore invoke an action the interface never offered.

\`\`\`http
POST /api/admin/invitations
Authorization: Bearer <lab-member-token>
Content-Type: application/json

{"email":"new-user@example.test"}
\`\`\`

The security boundary is the server's permission decision before the invitation is created.

### Scenario 2: Read permission becomes delete permission

A router requires authentication for every method but only checks permissions for \`GET\`. Adding \`DELETE\` under the same router accidentally lets every logged-in user perform a destructive operation.

## ❌ Vulnerable Code Example

\`\`\`javascript
app.post('/api/admin/invitations', authenticate, async (req, res) => {
  // Being logged in does not imply invitations:create permission.
  const invite = await invitations.create(req.body);
  res.status(201).json(invite);
});
\`\`\`

The handler also trusts caller-selected attributes such as the destination tenant. Function permission and object scoping need separate enforcement.

## ✅ Safer Code Example

\`\`\`javascript
// Pseudocode: policy and repository contracts belong to the application.
async function createStaffInvitation(actor, input) {
  await policy.require(actor, 'invitations:create', {
    tenantId: actor.tenantId
  }); // Denies by default and reads trusted membership state.

  const email = validateInvitationEmail(input.email);
  const invitation = await invitations.create({
    tenantId: actor.tenantId,
    email,
    role: 'member', // This operation cannot grant administrator access.
    invitedBy: actor.id
  });
  return { id: invitation.id, email: invitation.email };
}

app.post('/api/admin/invitations', authenticate, async (req, res, next) => {
  try {
    const result = await createStaffInvitation(req.user, req.body);
    res.status(201).json(result);
  } catch (error) {
    next(error); // Central handler maps denied permission to 403.
  }
});
\`\`\`

Putting authorization at the service boundary helps protect calls from HTTP handlers, scheduled jobs, and message consumers. Each caller still needs an explicit identity and policy. Do not invent a privileged default identity when a background task lacks one.

\`policy.require\` is an illustrative contract, not a library function. It must deny missing permissions and evaluate current membership in the relevant tenant. Validation and error handling helpers likewise need implementation before using this sketch in a real service.

## 🛡️ Design a Permission Matrix

| Caller | View members | Invite members | Grant administrator |
| --- | --- | --- | --- |
| Anonymous | Deny | Deny | Deny |
| Member | According to tenant policy | Deny | Deny |
| Tenant administrator | Own tenant | Own tenant | Separate elevated permission |
| Other tenant's administrator | Deny | Deny | Deny |

Use explicit capabilities rather than role-name comparisons scattered through handlers. Sensitive permission changes may also require recent authentication and an audit trail. For long-running jobs, re-evaluate authorization before sensitive execution when a user's rights may have changed after enqueueing.

## 🧩 More Examples and Solutions

### Example 3: Bulk actions skip individual authorization

A customer-management API checks a user's \`customers:archive\` capability once, then accepts a list of identifiers from multiple tenants. The operation permission is valid, but some targets are outside the caller's scope.

\`\`\`http
POST /api/customers/bulk-archive
Content-Type: application/json

{"ids":["tenant-a-customer","tenant-b-customer"]}
\`\`\`

**Solution:** combine operation authorization with target scoping. For an all-or-nothing contract, validate the entire target set before writing anything:

\`\`\`text
archiveCustomers(actor, ids):
  validate ids are distinct and the batch is bounded
  require customers:archive for actor's trusted tenant
  begin transaction
    load and lock all requested customers within that tenant
    if count does not equal requested count: reject without changes
    require archive permission for each customer's current state
    archive the authorized set
    append audit records
  commit
\`\`\`

This is service pseudocode; database locking and policy evaluation must fit the application's consistency model. Return a generic rejection when identifiers may be inaccessible, rather than revealing which ones exist in another tenant.

### Example 4: A background job outlives its creator's permission

An administrator starts an export, then loses access before the worker executes it. The worker trusts the job's saved \`isAdmin: true\` field and exports customer data anyway.

**Solution:** store the initiating actor, tenant, target scope, and requested operation, then re-check sensitive authority at execution. Never accept those identity fields directly from the request body.

\`\`\`python
# Pseudocode: all services below are application-owned dependencies.
def execute_export(job):
    actor = identities.load_active(job.initiated_by)
    policy.require(actor, "customers:export", tenant_id=job.tenant_id)
    rows = customers.stream_for_tenant(job.tenant_id)
    artifact = exports.write_encrypted(rows, expires_in_minutes=15)
    exports.attach_to_job(job.id, artifact.id)
\`\`\`

Protect the download separately. The person fetching the artifact needs current access to the job and tenant; a successful permission check at generation time is not a permanent download grant. Clean up partial exports on failure and retain only the minimum necessary data.

### Permission Enforcement Beyond the Router

Use the same service policy for REST, GraphQL, internal RPC, and queue consumers. If a machine identity legitimately performs an operation independently of a human, give it a dedicated, scoped capability and record both the machine and initiating user where relevant.

| Regression case | Expected result |
| --- | --- |
| Member invokes administrative bulk function | Denied before target lookup or writes |
| Administrator includes another tenant's target | Entire batch rejected under the stated contract |
| Administrator is revoked before export executes | Worker cancels or denies the job |
| User loses access before download | Artifact retrieval denied |
| New HTTP method exposes the same service | Existing service policy still runs |

## 🧪 Testing the Boundary

1. Enumerate routes and methods from the application router and API contract.
2. Run each privileged operation as anonymous, member, administrator, and another tenant's administrator.
3. Verify both the expected denial and the absence of side effects.
4. Exercise alternate versions, bulk operations, and background entry points.
5. Revoke a permission and confirm that stale sessions do not retain it beyond the intended policy.

## 📋 Security Checklist

- [ ] Deny operations unless a policy explicitly allows them.
- [ ] Evaluate permissions using server-trusted identity and membership.
- [ ] Scope privileged actions to the correct tenant and target.
- [ ] Protect every method and alternate entry point.
- [ ] Record actor, action, target, and outcome without logging secrets.

## 🔗 Related Risks

[API1:2023](/blog/API1:2023) covers object access; [API3:2023](/blog/API3:2023) covers fields. Passing a function permission check does not replace either.

## 📚 References

- [OWASP API Security — API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Authorization Testing Automation](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)


---`,g=`---
title: "API6:2023 — Unrestricted Access to Sensitive Business Flows"
slug: "API6:2023"
date: "2026-09-20"
excerpt: "Protect scarce inventory, promotions, reservations, and other sensitive workflows from automation that defeats business rules."
tags: ["owasp", "api"]
readingMinutes: 7
cover: "matrix"
---

# API6:2023 — Unrestricted Access to Sensitive Business Flows

> **Category:** OWASP API Security Top 10 (2023)  
> **Impact:** Depends on the exposed operation, data, and deployment.

## 🎯 What Is It?

**Unrestricted Access to Sensitive Business Flows** concerns legitimate functionality used in ways that harm the business or its users. The requests may be authenticated, well-formed, and cheap to process. The problem is the outcome of repeated or coordinated use.

Examples include monopolizing limited reservations, harvesting welcome rewards, and manufacturing engagement. The API can return exactly what its implementation intends while the product's fairness or economic assumptions fail.

## 🔬 Attack Surface Map

\`\`\`text
Discover valuable outcome
       ↓
Identify repeatable workflow
       ↓
Automate valid requests across accounts
       ↓
Consume inventory, rewards, or trust
\`\`\`

## 💥 Attack Scenarios

### Scenario 1: Reservation hoarding

A fictional workshop portal lets each account reserve seats for fifteen minutes. Repeated reservations hold all seats without completing checkout. Availability remains technically healthy, but real attendees cannot book.

A useful defense must consider active holds, their expiration, repeat behavior, and the event's capacity. Merely raising server capacity does not restore fair access.

### Scenario 2: Welcome-credit farming

A product awards credit after an account performs a simple onboarding action. An automated client repeatedly creates accounts and completes the action. A per-account request limit is ineffective because each account performs only a few requests.

## ❌ Vulnerable Code Example

\`\`\`python
# Pseudocode: neither uniqueness nor concurrency is controlled.
def claim_welcome_credit(user):
    if not claims.exists(user.id, "welcome"):
        wallet.add_credit(user.id, 500)
        claims.insert(user.id, "welcome")
    return {"status": "claimed"}
\`\`\`

Two concurrent requests can both pass the existence check. The credit and claim writes can also disagree if the process fails between them. Even after fixing those bugs, one account per reward may be the wrong business rule.

## ✅ Safer Transaction Design

\`\`\`text
claimWelcomeCredit(authenticatedActor):
  validate campaign eligibility using trusted server records
  derive the campaign's eligible customer identity

  begin database transaction
    insert claim(campaignId, eligibleCustomerId)
      protected by UNIQUE(campaignId, eligibleCustomerId)
      on conflict: return existing claim without adding credit

    insert wallet ledger entry referencing the unique claim
    insert outbox event referencing the claim
  commit transaction

  return the claim result
\`\`\`

This is architectural pseudocode. The uniqueness constraint, ledger change, and outbox write must share a transaction. If a payment or reward provider sits outside that transaction, use a worker with a stable idempotency key and reconcile provider results before retrying.

An idempotency key prevents an accidental retry from repeating one operation. It does not impose a campaign entitlement: a caller could otherwise select a new key each time. A unique claim per eligible customer enforces a separate business invariant.

## 🛡️ Controls That Match the Workflow

| Flow | Invariant | Additional control |
| --- | --- | --- |
| Seat reservation | Bounded active holds per eligible buyer | Short holds and fair waiting queue |
| Promotion | One entitlement per eligible customer | Risk review for linked accounts |
| Checkout | Stock cannot become negative | Atomic stock update and payment reconciliation |
| Review submission | Reviewer has a qualifying purchase | Duplicate and coordinated-behavior detection |

Define identity carefully. A newly created account, an email address, or an IP address is not necessarily a distinct customer. Shared networks also make IP-only rules unfair. Choose signals with product and privacy requirements in mind, and provide recovery paths for legitimate users caught by controls.

Risk-based friction can help, but a CAPTCHA alone does not enforce inventory, eligibility, or payment rules. Server-side state transitions remain necessary.

## 🧩 More Examples and Solutions

### Example 3: Checkout races oversell scarce inventory

Two buyers reach checkout with the last item in their carts. Both requests read \`available = 1\`, and each creates an order before decrementing stock. The database ends up with two orders for one unit.

**Solution:** reserve inventory with a conditional update inside the order transaction. The following PostgreSQL-style statement assumes the application has validated a positive integer quantity and authorized the purchase:

\`\`\`sql
UPDATE inventory
SET available = available - $1
WHERE sku = $2
  AND available >= $1
RETURNING sku, available;
\`\`\`

Require exactly one returned row before inserting the reservation. If any later write fails, roll back the transaction. Store a reservation identifier and expiry, then process payment through a recoverable workflow instead of holding a database transaction open during a remote call.

An expiry worker must release a reservation once only. Make \`held → paid\`, \`held → expired\`, and \`held → cancelled\` conditional state transitions so a delayed payment callback cannot sell inventory that has already been released without a defined reconciliation policy.

### Example 4: Review rewards survive immediate refunds

A store awards loyalty points after a review. Automated buyers place qualifying orders, collect points, and refund the purchases. Each individual endpoint behaves correctly, but the combined workflow creates unearned rewards.

**Solution:** define eligibility across the order lifecycle. For this example, points become redeemable only after the return window closes. A refund before that date cancels pending points; later adjustments use a recorded compensating ledger entry.

\`\`\`text
Order delivered → review accepted → points pending
      │                                  │
      └─ eligible refund ───────────────→ points cancelled
                                         │
Return window closes with valid order ──→ points available
\`\`\`

Do not implement refunds by deleting historical rewards. Ledger entries let operators explain the balance and recover after retries. Enforce a unique reward entitlement per qualifying purchase, and ensure different event identifiers cannot issue the same entitlement twice.

### Operational Solutions for Automated Abuse

Use flow metrics as well as request counts: reservation-to-payment ratio, reward-to-refund ratio, repeated cancellations, and purchase concentration can reveal harm that server latency cannot. Compare patterns within the product's normal usage context before introducing friction.

Add a queue for limited releases, bounded active holds, and progressive review for unusual behavior. Keep an accessible alternative when a challenge fails. Controls should make the business invariant enforceable without excluding legitimate bulk buyers or users sharing a network.

| Controlled experiment | Invariant to verify |
| --- | --- |
| Two checkouts for one remaining unit | At most one active reservation succeeds |
| Payment callback races hold expiry | One consistent final state and reconciliation path |
| Review event is delivered twice | One pending reward |
| Refund occurs before reward maturity | No redeemable points from that purchase |
| Many low-rate accounts reserve inventory | Aggregate abuse is visible to flow monitoring |

## 🧪 Testing the Boundary

1. Describe the forbidden business outcome before writing requests.
2. Use fixture accounts to exercise a normal completion and an abandoned flow.
3. In a controlled test, send two simultaneous reward claims; verify one ledger credit.
4. Retry with the same and different idempotency keys; verify the entitlement stays bounded.
5. Exercise expiration, cancellation, refunds, and provider timeouts.
6. Check that shared-network users still have a viable legitimate path.

## 📋 Security Checklist

- [ ] Identify valuable workflows with product owners.
- [ ] Enforce business invariants atomically.
- [ ] Separate retry deduplication from entitlement rules.
- [ ] Combine account-level controls with appropriate abuse signals.
- [ ] Monitor unusual completion, abandonment, and reward patterns.
- [ ] Test fairness and recovery as well as denial.

## 🔗 Related Risks

[API4:2023](/blog/API4:2023) limits resource use. API6 protects business outcomes even when the system is operating within its capacity.

## 📚 References

- [OWASP API Security — API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
- [OWASP Business Logic Security](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)
- [OWASP Bot Management and Anti-Automation](https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html)
- [OWASP Abuse Case Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html)


---`,v=`---
title: "API7:2023 — Server Side Request Forgery"
slug: "API7:2023"
date: "2026-09-20"
excerpt: "Keep user-controlled URLs from turning API servers into network proxies with destination policies, constrained egress, and bounded fetches."
tags: ["owasp", "api"]
readingMinutes: 7
cover: "matrix"
---

# API7:2023 — Server Side Request Forgery

> **Category:** OWASP API Security Top 10 (2023)  
> **Impact:** Depends on the exposed operation, data, and deployment.

## 🎯 What Is It?

**Server Side Request Forgery (SSRF)** happens when an API can be induced to make an unintended outbound request. URL previews, remote imports, webhook delivery, and document converters commonly accept destinations or follow links.

The server may reach services the caller cannot reach directly. A fetch performed with the server's network position or credentials can therefore cross a trust boundary even if the fetched response is never returned to the caller.

## 🔬 Attack Surface Map

\`\`\`text
User input → URL parser → DNS resolution → connection → redirects
                              ↓               ↓
                        destination policy   egress policy
\`\`\`

Validate the destination actually connected to, not just how the original string looks.

## 💥 Attack Scenarios

### Scenario 1: A remote preview reaches a private service

A fictional preview endpoint downloads any URL supplied in a JSON body. A caller selects a private service instead of a public document. The preview handler returns internal content using its own network access.

### Scenario 2: An approved link redirects elsewhere

The API approves an initial hostname but automatically follows a redirect to an unapproved destination. Validation applied only to the first URL does not constrain the final connection.

## ❌ Vulnerable Code Example

\`\`\`javascript
app.post('/api/preview', authenticate, async (req, res) => {
  const response = await fetch(req.body.url);
  res.send(await response.text());
});
\`\`\`

The caller selects a destination, the client follows redirects by default, and the response is buffered without a size bound. Returning the downloaded document as active content can introduce additional browser-side risks.

## ✅ Safer Design: Accept a Resource Identifier

When a feature imports documents from one trusted provider, avoid accepting arbitrary URLs at all:

\`\`\`javascript
// Illustrative Node.js helper. Fixed origin requires controlled DNS and egress.
async function loadProviderDocument(documentId) {
  if (typeof documentId !== 'string' ||
      !/^[A-Za-z0-9_-]{1,64}$/.test(documentId)) {
    throw new Error('Invalid document identifier');
  }

  const url = new URL(\`/documents/\${documentId}\`, 'https://docs.example.test');
  const response = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(3000),
    headers: { Accept: 'text/plain' }
  });
  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new Error('Provider request failed');
  }

  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 64 * 1024) throw new Error('Document too large');
      chunks.push(Buffer.from(value));
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString('utf8');
}
\`\`\`

\`example.test\` is a placeholder for a configured provider. This helper constrains URL construction, rejects redirects, and bounds response bytes. The calling endpoint must authenticate and authorize the document request and return data with an appropriate content type. Do not forward a user's bearer token or cookies to the provider.

## 🛡️ When Arbitrary Destinations Are Required

A webhook product may genuinely need customer-selected destinations. Use a dedicated fetch service or egress proxy with an explicit policy:

- Parse URLs with a standard parser; allow only required schemes and ports.
- Reject embedded credentials and ambiguous or invalid hostnames.
- Resolve and classify all destination addresses, including IPv6 and mapped addresses.
- Block private, loopback, link-local, reserved, and infrastructure destinations as appropriate to the deployment.
- Bind the validated destination to the connection so DNS changes cannot bypass validation.
- Reject redirects or apply the same checks at every hop.
- Constrain outbound network access independently of application checks.

A hostname allowlist based on substring matching is insufficient. Likewise, resolving a hostname once and letting the HTTP client resolve it again can create a validation-to-connection race. These are reasons to centralize outbound fetching rather than copy a short URL filter into every handler.

## 🧩 More Examples and Solutions

### Example 3: A document renderer fetches embedded resources

A PDF service accepts HTML and validates the main document's origin. During rendering, the browser loads images, stylesheets, frames, and fonts from URLs inside the document. The renderer's secondary requests escape the original validation.

\`\`\`html
<!-- Fictional internal name used only in a controlled fixture. -->
<img src="https://internal-fixture.example.test/status" alt="preview">
\`\`\`

**Solution:** isolate rendering and constrain every resource load. If remote resources are unnecessary, disable network access for the renderer and provide approved assets locally. If they are required, route all traffic through the same destination-enforcing egress service, including subresources and redirects.

Give the renderer no cloud credentials or application secrets. Disable unnecessary file access, use a read-only base filesystem with bounded temporary storage, and enforce a job deadline. Blocking only the initial navigation leaves the rendering engine as a second fetch client with its own behavior.

### Example 4: A queued webhook uses stale validation

A webhook destination is checked when a customer registers it. Days later, a delivery worker resolves the hostname again. Its address has changed, so registration-time approval no longer describes the connection.

**Solution:** validate at delivery time and bind the approved address to that connection. Preserve the hostname for TLS certificate verification; replacing a hostname with an IP and disabling certificate checks weakens a different boundary.

\`\`\`text
Illustrative destination-enforcing egress contract:
  parse destination under the allowed scheme/port policy
  resolve all addresses with a controlled resolver
  reject destinations outside the permitted network classes
  select an approved address and connect to that exact address
  verify TLS for the original approved hostname
  send only the delivery service's intended headers
  reject redirects, or repeat all checks for every new hop
\`\`\`

This contract needs a network client or proxy capable of controlling resolution and connection together. It is not safely implemented by a URL regular expression followed by an unconstrained \`fetch()\`.

### Choosing an SSRF Solution

| Feature | Preferred boundary |
| --- | --- |
| Import from a single provider | Fixed origin and validated resource identifier |
| Render uploaded documents | Network-disabled sandbox where possible |
| Deliver customer webhooks | Dedicated worker with destination-enforcing egress |
| Fetch public previews | Isolated fetch service with bounded responses |
| Access an internal dependency | Explicit internal service identity and narrow destination policy |

Separate public URL fetching from legitimate internal service traffic so a broad exception for one does not weaken the other. Network controls should prevent the worker from bypassing its proxy through another protocol or direct socket connection.

### Additional Regression Fixtures

Test resource subrequests, redirects, address changes between deliveries, and mixed IPv4/IPv6 answers using your own fixtures. The assertion is **no connection reached the blocked fixture**, not merely that the API returned an error: a request may already have caused a side effect before the error was produced.

## 🧪 Testing the Boundary

Use controlled test endpoints and mocked DNS; do not probe real internal infrastructure:

1. Confirm the approved provider path works.
2. Reject malformed identifiers and unsupported URL inputs.
3. Make a test endpoint redirect to a blocked destination and verify no second connection occurs.
4. Simulate DNS changes and IPv4/IPv6 variants in the egress component.
5. Return a slow or oversized body and verify cancellation and bounded memory use.
6. Check logs for blocked destinations without recording credentials or sensitive query strings.

## 📋 Security Checklist

- [ ] Prefer server-selected destinations and client-selected identifiers.
- [ ] Enforce destination policy at connection time.
- [ ] Constrain redirects, protocols, ports, and outbound credentials.
- [ ] Use network egress controls and isolated fetch workers.
- [ ] Bound time, response bytes, and concurrent fetches.

## 🔗 Related Risks

[API10:2023](/blog/API10:2023) covers whether a provider's response is trustworthy after a permitted connection succeeds.

## 📚 References

- [OWASP API Security — API7:2023](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)


---`,b=`---
title: "API8:2023 — Security Misconfiguration"
slug: "API8:2023"
date: "2026-09-20"
excerpt: "Harden the configuration around APIs: remove debug exposure, constrain browser access, protect transport, and keep deployment settings consistent."
tags: ["owasp", "api"]
readingMinutes: 7
cover: "matrix"
---

# API8:2023 — Security Misconfiguration

> **Category:** OWASP API Security Top 10 (2023)  
> **Impact:** Depends on the exposed operation, data, and deployment.

## 🎯 What Is It?

**Security Misconfiguration** occurs when an API or its supporting infrastructure runs with settings that expose unnecessary capabilities or weaken security boundaries. Correct business logic cannot compensate for a public debugger, unsafe proxy trust, or a production service using development defaults.

Configuration spans the gateway, application, runtime, storage, and deployment pipeline. Review the effective deployed settings, not just the defaults committed to source control.

## 🔬 Attack Surface Map

| Layer | Example mistake | Possible effect |
| --- | --- | --- |
| Application | Debug errors returned to clients | Internal paths and implementation details leak |
| Browser access | Arbitrary origins trusted with credentials | Untrusted sites can read permitted browser responses |
| Gateway | Untrusted forwarding headers accepted | Client identity or scheme assumptions become unreliable |
| Operations | Management endpoints exposed publicly | Sensitive operational access |
| Deployment | Old components or unused services retained | Avoidable attack surface |

## 💥 Attack Scenarios

### Scenario 1: Debug output in production

A fictional API encounters a database error and returns the exception object and stack trace. Repeated malformed requests reveal internal paths, query structure, and implementation details. The application should return an opaque error identifier and keep diagnostic details in restricted logs.

### Scenario 2: Credentialed CORS reflects every origin

A server echoes any incoming \`Origin\` and allows credentials. Depending on authentication and browser cookie behavior, an untrusted page may read responses belonging to a signed-in user. A wildcard origin with credentials is rejected by browsers, but reflecting arbitrary origins creates a different configuration mistake.

## ❌ Vulnerable Code Example

\`\`\`javascript
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

app.use((error, req, res, next) => {
  res.status(500).json({ error: error.message, stack: error.stack });
});
\`\`\`

CORS controls browser response access; it does not authenticate a caller or stop non-browser clients. It also does not replace CSRF protection for cookie-authenticated state changes.

## ✅ Safer Configuration Example

For a single-origin application, avoid enabling cross-origin access unless needed. If a separate trusted frontend requires credentialed CORS, make that relationship explicit:

\`\`\`javascript
// Illustrative middleware for an API with GET/POST and JSON requests.
const allowedOrigins = new Set(['https://app.example.test']);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  res.vary('Origin');
  if (origin && !allowedOrigins.has(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next(); // Authentication, authorization, and CSRF checks still follow.
});

// Register last, after routes. logger must redact sensitive values.
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const errorId = crypto.randomUUID();
  logger.error({ errorId, error }, 'Request failed');
  res.status(500).json({ error: 'Internal server error', errorId });
});
\`\`\`

The sketch assumes \`crypto\` is imported from \`node:crypto\` and a configured redacting logger exists. Production error handling should also map known validation and authorization failures to their intended status codes instead of turning every error into a \`500\`.

## 🛡️ Deployment Baseline

Keep transport, proxy, and application settings aligned. Terminate TLS at the intended gateway and secure the remaining hop according to the deployment's trust model. Only trust forwarding headers from the actual controlled proxy path.

Remove sample applications and unused methods. Keep health checks minimal and separate privileged diagnostics from public availability checks. Restrict management access by both network policy and authentication.

Store environment-specific configuration in a reviewed deployment system. Validate required settings at startup and fail deployment if security-critical values are missing. Compare live configuration with the approved baseline to catch manual changes and environment drift.

## 🧩 More Examples and Solutions

### Example 3: Personalized responses enter a shared cache

A reverse proxy caches \`/api/me\` using only the URL. The application returns user-specific JSON without an explicit cache policy. A later caller can receive an earlier caller's profile.

**Solution:** use a deliberate policy for authenticated responses and verify that the proxy obeys it. For sensitive profile data, a straightforward application default is:

\`\`\`javascript
// Register before the sensitive routes; proxy configuration must agree.
app.use('/api/me', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});
\`\`\`

Exclude these paths from CDN or gateway caching, and ensure error responses do not carry private data either. When personalized caching is truly required, design identity-aware cache keys and invalidation explicitly. Setting \`Vary: Origin\` only distinguishes origins; it does not partition responses by account.

### Example 4: Development settings silently reach production

A deployment starts without the expected frontend-origin setting and falls back to permissive cross-origin access. Another deployment enables a debug listener because an environment value was parsed as a truthy string.

**Solution:** validate security-critical settings before listening for requests. The following example accepts only an exact production configuration shape for these two values:

\`\`\`javascript
function validateProductionSettings(env) {
  if (env.NODE_ENV !== 'production') {
    throw new Error('Production mode is required');
  }
  if (env.DEBUG_ENABLED !== 'false') {
    throw new Error('Debug must be explicitly disabled');
  }
  const origin = new URL(env.FRONTEND_ORIGIN);
  if (origin.protocol !== 'https:' || origin.username || origin.password ||
      origin.pathname !== '/' || origin.search || origin.hash) {
    throw new Error('Expected an HTTPS frontend origin');
  }
  return { frontendOrigin: origin.origin, debugEnabled: false };
}
\`\`\`

Call this from the production startup path before binding ports. The deployment system must restrict who can change the origin: syntactically valid configuration is not necessarily approved configuration. Validate required secret references separately without printing their values in startup errors.

### Configuration Review and Recovery

Maintain an approved baseline for each environment and compare effective settings after deployment. Check the gateway and application together: either can re-enable a route, add permissive headers, or undermine a body-size limit.

If credentials were exposed through configuration or logs, removing the visible copy is insufficient. Revoke or rotate the affected credentials, review their use, and replace the unsafe logging or deployment path. Give each environment distinct credentials to limit the scope of such an incident.

| Regression case | Expected result |
| --- | --- |
| Two accounts request \`/api/me\` through the CDN | Neither receives the other's response |
| \`DEBUG_ENABLED=true\` in production | Startup fails before serving requests |
| Frontend origin is absent or includes credentials | Startup rejects the configuration |
| Public request reaches diagnostics | Denied under the intended access policy |
| Proxy configuration changes | Automated baseline comparison flags drift |

## 🧪 Testing the Boundary

1. Trigger a controlled server error and confirm the response contains no stack trace or secret.
2. Exercise permitted and untrusted browser origins, including preflight requests.
3. Verify authentication remains required when \`Origin\` is absent.
4. Inspect externally reachable health and management paths.
5. Test forwarding-header behavior through the actual staging proxy chain.
6. Confirm the built artifact starts with production configuration and no debug listener.

## 📋 Security Checklist

- [ ] Disable debug features and remove unused services.
- [ ] Use intentional TLS and proxy trust settings.
- [ ] Restrict CORS to required origins, methods, and headers.
- [ ] Protect cookie-authenticated writes against CSRF.
- [ ] Return generic unexpected errors and redact server logs.
- [ ] Patch components and detect deployment configuration drift.

## 🔗 Related Risks

[API9:2023](/blog/API9:2023) helps ensure the same baseline covers forgotten hosts and older versions.

## 📚 References

- [OWASP API Security — API8:2023](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)


---`,w=`---
title: "API9:2023 — Improper Inventory Management"
slug: "API9:2023"
date: "2026-09-20"
excerpt: "Keep track of API hosts, versions, owners, data flows, and retirement plans so forgotten endpoints do not bypass current security controls."
tags: ["owasp", "api"]
readingMinutes: 7
cover: "matrix"
---

# API9:2023 — Improper Inventory Management

> **Category:** OWASP API Security Top 10 (2023)  
> **Impact:** Depends on the exposed operation, data, and deployment.

## 🎯 What Is It?

**Improper Inventory Management** means the organization lacks an accurate picture of its API exposure and lifecycle. A well-maintained current API does not protect an older version, a forgotten preview deployment, or an undocumented partner endpoint.

An inventory needs more than endpoint names. It should connect deployed hosts and operations to accountable owners, environments, access policies, sensitive data, and retirement decisions.

## 🔬 Attack Surface Map

\`\`\`text
Source routes ───────┐
Gateway routes ──────┤
Cloud deployments ──┼─→ Reconciled inventory → owner and lifecycle policy
DNS and certificates┤
Observed traffic ───┘
\`\`\`

No single source is complete. A specification may describe an endpoint that was never deployed, while a gateway may expose an operation missing from the specification.

## 💥 Attack Scenarios

### Scenario 1: The old version skips a new control

A fictional service deploys \`/v2/accounts\` with stronger authorization. Its old \`/v1/accounts\` route remains active for an unknown client. The team tests only v2, leaving the same underlying account data reachable through the outdated path.

### Scenario 2: Preview deployment uses production data

An abandoned preview environment retains a production database credential. Its host is publicly reachable, but the deployment is absent from the team's service list and no longer receives configuration updates.

## ❌ Vulnerable Deployment Pattern

\`\`\`yaml
# Illustrative inventory: describes a service but omits its exposure.
service: customer-api
version: v2
# Missing hosts, old versions, owner, data classification, and retirement plan.
\`\`\`

A manually maintained label does not show which routes are actually accessible. Deleting old documentation also does not disable a deployed endpoint.

## ✅ A More Useful Inventory Record

\`\`\`yaml
# Example schema for an internal catalog, not a standard deployment format.
service: customer-api
owner: identity-platform
on_call: identity-platform-primary
environment: production
hosts:
  - api.example.test
base_path: /v2
contract: contracts/customer-v2.openapi.yaml
exposure: public
authentication: oauth2
policy: customer-api-v2
sensitive_data:
  - customer-contact-details
upstream_dependencies:
  - customer-database
external_recipients: []
lifecycle:
  status: active
  last_reviewed: '2026-09-20'
  next_review: '2026-12-20'
\`\`\`

Record deprecated versions separately while they remain reachable. Each needs an owner, supported consumers, a shutdown date, and a plan to maintain security controls until retirement. Do not assume a version is harmless because traffic is low.

## ✅ Check Route Drift in Delivery

\`\`\`python
# Simplified CI helper: adapters must produce normalized method/path pairs.
def assert_routes_documented(deployed_routes, documented_routes):
    deployed = {(method.upper(), path) for method, path in deployed_routes}
    documented = {(method.upper(), path) for method, path in documented_routes}
    undocumented = deployed - documented
    if undocumented:
        details = ", ".join(f"{m} {p}" for m, p in sorted(undocumented))
        raise RuntimeError(f"Undocumented deployed routes: {details}")
\`\`\`

The difficult part is supplying trustworthy inputs. Extract deployed routes from router or gateway configuration and documented routes from the API contract. Normalize path parameters and account explicitly for generated \`HEAD\` or \`OPTIONS\` routes so noisy false positives do not make teams ignore the check.

This helper detects one kind of drift. It cannot discover an unknown host, identify data recipients, or prove that documented authorization rules are enforced. Pair it with deployment discovery and security tests.

## 🛡️ Retire an API Deliberately

1. Identify consumers through traffic and client registrations.
2. Publish a migration path and deadline through the team's normal process.
3. Keep the old version patched and monitored during migration.
4. Disable obsolete routes at both gateway and application layers where applicable.
5. Remove obsolete deployments and revoke their dedicated credentials.
6. Verify that the old origin is no longer reachable through a bypass path.

Retirement should preserve any required audit records while removing access to live data. If a temporary rollback path exists, give it an owner, an expiry, and the same security controls as an active service.

## 🧩 More Examples and Solutions

### Example 3: A partner API shares undocumented customer data

A fulfillment integration receives contact details through an old partner route. The route is not included in the public API contract, so a data-minimization review overlooks it. The integration continues exporting a field the main API stopped exposing.

**Solution:** maintain a data-flow inventory alongside endpoint inventory. Record the sender, recipient, purpose, fields, credential owner, retention expectations, and exit process. Review changes when a payload or recipient changes, not only when a new route appears.

\`\`\`yaml
# Illustrative catalog extension.
data_flow:
  id: fulfillment-contact-export
  source_service: orders-api
  recipient: contracted-fulfillment-provider
  purpose: deliver-confirmed-orders
  fields: [recipient_name, delivery_address]
  credential_owner: fulfillment-platform
  contract: contracts/fulfillment-export.openapi.yaml
  retention_policy: policies/fulfillment-retention.md
  offboarding_runbook: runbooks/revoke-fulfillment-access.md
\`\`\`

Keep secret values out of the catalog. It should identify who can rotate a credential and where its managed reference lives, not become another credential store.

### Example 4: A temporary route becomes a permanent bypass

A migration introduces \`/migration/customers\` for a short-lived internal tool. The migration finishes, but the route stays deployed behind a public gateway. No owner receives follow-up because it was never registered as an API asset.

**Solution:** make temporary exposure expire through the deployment process. Require an owner and retirement date for exceptions, then block new releases containing overdue exceptions until they are removed or explicitly reviewed.

\`\`\`python
from datetime import date

# Example CI policy for temporary-route records.
def check_temporary_routes(records, today):
    for record in records:
        if not record.get("owner"):
            raise ValueError("Temporary route needs an owner")
        if not record.get("retire_on"):
            raise ValueError("Temporary route needs a retirement date")
        deadline = date.fromisoformat(record["retire_on"])
        if deadline <= today:
            raise ValueError(f"Temporary route overdue: {record['route']}")
\`\`\`

A CI failure does not remove a route already running. Pair this check with scheduled discovery, owner notifications through the team's established system, and an operational removal process. An automatic shutdown also needs an availability plan for any still-supported consumers.

### From Discovery to a Verified Fix

| Finding | Follow-up | Completion evidence |
| --- | --- | --- |
| Host absent from inventory | Identify deployment and accountable owner | Catalog entry reconciled to infrastructure |
| Deployed method missing from contract | Document intentionally or remove | Contract comparison passes |
| Deprecated route still receives traffic | Identify consumers and migrate | Retirement verification passes |
| Preview host accesses production data | Remove connection and rotate its credential | Access test fails from preview environment |
| External recipient is undocumented | Review payload, purpose, and access | Approved data-flow record and minimized payload |

Use deployed evidence to close findings. A merged deletion is not proof of retirement if an old instance or direct origin still serves the route. Conversely, inventory metadata does not replace authentication, property filtering, or permission enforcement on the endpoints it describes.

## 🧪 Testing the Boundary

Compare the catalog with controlled cloud accounts, gateways, DNS, and observed traffic. Review unknown entries with their owners. Exercise old routes in staging and confirm the intended retirement response, such as \`404\` or \`410\`, without a working direct-origin fallback.

Check non-production deployments for production credentials and data connections. Validate that external integrations and sensitive data recipients are represented in the inventory, not only incoming HTTP endpoints.

## 📋 Security Checklist

- [ ] Inventory hosts, environments, versions, operations, and owners.
- [ ] Record authentication, data sensitivity, and external data flows.
- [ ] Compare contracts with deployed routes during delivery.
- [ ] Discover and review unexpected infrastructure regularly.
- [ ] Give every deprecated version a maintained retirement plan.
- [ ] Revoke obsolete access when deployments are removed.

## 🔗 Related Risks

Inventory makes [API8:2023](/blog/API8:2023) configuration reviews and [API5:2023](/blog/API5:2023) permission tests cover the complete deployed surface.

## 📚 References

- [OWASP API Security — API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)
- [OWASP Attack Surface Analysis](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)
- [OpenAPI Specification 3.1.1](https://spec.openapis.org/oas/v3.1.1.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)


---`,A=Object.assign({"../blogs/API10:2023.md":u,"../blogs/API1:2023.md":p,"../blogs/API2:2023.md":h,"../blogs/API3:2023.md":m,"../blogs/API4:2023.md":f,"../blogs/API5:2023.md":y,"../blogs/API6:2023.md":g,"../blogs/API7:2023.md":v,"../blogs/API8:2023.md":b,"../blogs/API9:2023.md":w}),k=/^---\s*\n([\s\S]*?)\n---\s*\n?/;function I(n){const t=n.match(k);if(!t)return{data:{},content:n};const r=n.slice(t[0].length),a={};return t[1].split(/\r?\n/).forEach(i=>{if(!i.trim()||i.trim().startsWith("#"))return;const s=i.indexOf(":");if(s===-1)return;const o=i.slice(0,s).trim();let e=i.slice(s+1).trim();if(e.startsWith("[")&&e.endsWith("]")){const c=e.slice(1,-1).trim();a[o]=c?c.split(",").map(l=>l.trim().replace(/^["']|["']$/g,"")):[];return}if((e.startsWith('"')&&e.endsWith('"')||e.startsWith("'")&&e.endsWith("'"))&&(e=e.slice(1,-1)),e==="true"||e==="false"){a[o]=e==="true";return}if(e!==""&&!isNaN(Number(e))){a[o]=Number(e);return}a[o]=e}),{data:a,content:r}}function S(n,t){const{data:r,content:a}=I(t),i=n.split("/").pop()?.replace(/\.md$/,"")??"post",s=a.split(/\s+/).filter(Boolean).length;return{title:String(r.title??"Untitled"),slug:String(r.slug??i),date:String(r.date??new Date().toISOString().slice(0,10)),excerpt:String(r.excerpt??""),tags:Array.isArray(r.tags)?r.tags.map(String):[],readingMinutes:Number(r.readingMinutes??Math.max(1,Math.round(s/220))),cover:r.cover?String(r.cover):void 0,content:a}}const d=Object.entries(A).map(([n,t])=>S(n,t)).sort((n,t)=>n.date<t.date?1:-1);function x(){return d}function _(n){return d.find(t=>t.slug===n)}export{x as getAllPosts,_ as getPostBySlug};
