# 1. High-Level Architecture

```mermaid
flowchart TD
    U[User]

    FE[Auth Flow Engine]

    IM[Identity Method]
    IR[Identity Registry]
    LP[Linking Policy]
    SS[Session Service]

    DB1[(users)]
    DB2[(identities)]
    DB3[(provider tables)]

    U --> FE

    FE --> IM
    FE --> IR
    FE --> LP
    FE --> SS

    IM --> DB3
    IR --> DB2
    IR --> DB1
```

---

# 2. Responsibility Boundaries

```mermaid
flowchart LR
    A[Identity Method]
    B[Auth Flow Engine]
    C[Identity Registry]
    D[Session Service]

    A -->|"Validate proof"| B
    B -->|"Resolve user"| C
    B -->|"Issue session"| D
```

---

# 3. Complete Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant F as Auth Flow Engine
    participant M as Identity Method
    participant R as Identity Registry
    participant P as Linking Policy
    participant S as Session Service

    U->>F: StartAuth(method)

    F->>M: Start()

    M->>F: ChallengeStep
    F->>U: Challenge

    U->>F: ChallengeProof

    F->>M: Continue(proof)

    M->>M: Validate proof

    alt Invalid Proof
        M->>F: Failure
        F->>U: Authentication Failed
    else Valid Proof
        M->>F: VerifiedIdentity(provider, subject, claims)

        F->>R: LookupIdentity(provider, subject)

        alt Identity Exists
            R->>F: Existing UserID
        else Identity Does Not Exist
            F->>R: Resolve/Create User
            R->>F: New UserID

            F->>P: ValidateLink(user, identity)

            alt Link Conflict
                P->>F: Reject
                F->>U: Manual Linking Required
            else Allowed
                P->>F: Allow
                F->>R: Create Identity Mapping
            end
        end

        F->>S: CreateSession(user)

        S->>F: SessionToken

        F->>U: Authenticated(SessionToken)
    end
```

---

# 4. Passkey Internal Flow

Passkey method 自己的 protocol state machine：

```mermaid
stateDiagram-v2
    [*] --> START

    START --> CHALLENGE_CREATED
    CHALLENGE_CREATED --> ASSERTION_RECEIVED

    ASSERTION_RECEIVED --> VERIFY_ASSERTION

    VERIFY_ASSERTION --> FAILED
    VERIFY_ASSERTION --> VERIFIED

    VERIFIED --> [*]
    FAILED --> [*]
```

---

# 5. OIDC Internal Flow

```mermaid
stateDiagram-v2
    [*] --> START

    START --> REDIRECT_TO_PROVIDER
    REDIRECT_TO_PROVIDER --> CALLBACK_RECEIVED

    CALLBACK_RECEIVED --> EXCHANGE_TOKEN
    EXCHANGE_TOKEN --> VERIFY_ID_TOKEN

    VERIFY_ID_TOKEN --> FAILED
    VERIFY_ID_TOKEN --> VERIFIED

    VERIFIED --> [*]
    FAILED --> [*]
```

---

# 6. Email OTP Internal Flow

```mermaid
stateDiagram-v2
    [*] --> START

    START --> SEND_OTP
    SEND_OTP --> WAIT_FOR_CODE

    WAIT_FOR_CODE --> VERIFY_OTP

    VERIFY_OTP --> FAILED
    VERIFY_OTP --> VERIFIED

    VERIFIED --> [*]
    FAILED --> [*]
```

---

# 7. Canonical Identity Resolution Flow

這是 architecture 最重要的部分。

```mermaid
flowchart TD
    A[Verified Identity]

    A --> B["provider + subject"]

    B --> C{Identity Exists?}

    C -->|Yes| D[Return UserID]

    C -->|No| E[Resolve Existing User]
    E --> F{User Exists?}

    F -->|No| G[Create User]

    F -->|Yes| H[Use Existing User]

    G --> I[Create Identity Mapping]
    H --> I

    I --> J[Return UserID]
```

---

# 8. Data Model Relationships

```mermaid
erDiagram
    USERS ||--o{ IDENTITIES : owns

    IDENTITIES ||--o| PASSKEY_CREDENTIALS : has
    IDENTITIES ||--o| OIDC_IDENTITIES : has
    IDENTITIES ||--o| EMAIL_IDENTITIES : has

    USERS {
        uuid id
    }

    IDENTITIES {
        uuid id
        uuid user_id
        string provider
        string subject
    }

    PASSKEY_CREDENTIALS {
        uuid identity_id
        bytes credential_id
        bytes public_key
        int sign_count
    }

    OIDC_IDENTITIES {
        uuid identity_id
        string issuer
        string refresh_token
    }

    EMAIL_IDENTITIES {
        uuid identity_id
        string email
        bool verified
    }
```

---

# 9. Registration / Linking Flow

當 identity 不存在時：

```mermaid
sequenceDiagram
    participant F as Flow
    participant M as Method
    participant R as Registry
    participant P as Policy

    M->>F: VerifiedIdentity

    F->>R: FindIdentity(provider, subject)

    R->>F: NotFound

    F->>R: ResolveUserByClaims(email)

    alt Existing User
        R->>F: Existing User
    else No User
        R->>F: Create New User
    end

    F->>P: ValidateLink()

    alt Conflict
        P->>F: Reject
    else Allowed
        P->>F: Allow
        F->>R: Create Identity Mapping
    end
```

---

# 10. Future Scalability Model

這個 architecture 最重要的價值：

```mermaid
flowchart TD
    A[Auth Flow Engine]

    A --> B[Passkey]
    A --> C[OIDC]
    A --> D[Email OTP]
    A --> E[SAML]
    A --> F[LDAP]
    A --> G[Magic Link]
    A --> H[Wallet Login]
```

Flow 永遠只需要：

```text id="9x0jsf"
provider + subject
```

不需要理解任何 provider internals。

---

# 11. Recommended Final Structure

```text id="qt7l37"
Auth Flow Engine
├── Session Lifecycle
├── User Resolution
├── Linking Orchestration
├── Conflict Handling
└── Token Issuance

Identity Methods
├── Passkey
├── OIDC
├── Email OTP
└── Future Providers

Identity Registry
├── identities table
└── provider+subject mapping

Provider Schemas
├── passkey_credentials
├── oidc_identities
└── email_identities
```
