const l=`---
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

---`,p=`---
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

---`,h=Object.assign({"../blogs/API1:2023.md":l,"../blogs/API2:2023.md":p}),m=/^---\s*\n([\s\S]*?)\n---\s*\n?/;function g(n){const t=n.match(m);if(!t)return{data:{},content:n};const r=n.slice(t[0].length),s={};return t[1].split(/\r?\n/).forEach(i=>{if(!i.trim()||i.trim().startsWith("#"))return;const o=i.indexOf(":");if(o===-1)return;const a=i.slice(0,o).trim();let e=i.slice(o+1).trim();if(e.startsWith("[")&&e.endsWith("]")){const c=e.slice(1,-1).trim();s[a]=c?c.split(",").map(u=>u.trim().replace(/^["']|["']$/g,"")):[];return}if((e.startsWith('"')&&e.endsWith('"')||e.startsWith("'")&&e.endsWith("'"))&&(e=e.slice(1,-1)),e==="true"||e==="false"){s[a]=e==="true";return}if(e!==""&&!isNaN(Number(e))){s[a]=Number(e);return}s[a]=e}),{data:s,content:r}}function k(n,t){const{data:r,content:s}=g(t),i=n.split("/").pop()?.replace(/\.md$/,"")??"post",o=s.split(/\s+/).filter(Boolean).length;return{title:String(r.title??"Untitled"),slug:String(r.slug??i),date:String(r.date??new Date().toISOString().slice(0,10)),excerpt:String(r.excerpt??""),tags:Array.isArray(r.tags)?r.tags.map(String):[],readingMinutes:Number(r.readingMinutes??Math.max(1,Math.round(o/220))),cover:r.cover?String(r.cover):void 0,content:s}}const d=Object.entries(h).map(([n,t])=>k(n,t)).sort((n,t)=>n.date<t.date?1:-1);function y(){return d}function f(n){return d.find(t=>t.slug===n)}export{y as getAllPosts,f as getPostBySlug};
