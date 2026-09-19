# GateKeeper

A modular, production-ready Identity and Access Management (IAM) service built with FastAPI.

GateKeeper is designed as a standalone authentication and authorization platform that integrates across diverse clients (web, mobile, third-party backends). It centralizes user identity, token lifecycles, role-based access control (RBAC), and session validation through standard REST interfaces.

---

## Architecture Overview

```text
+-------------------+   +--------------------+   +---------------------+
| Web Application   |   | Mobile Application |   | Admin Dashboard     |
+---------+---------+   +---------+----------+   +----------+----------+
          |                       |                         |
          +-----------------------+-------------------------+
                                  |
                                  v
                       +---------------------+
                       | GateKeeper IAM API  |
                       |      (FastAPI)      |
                       +----------+----------+
                                  |
               +------------------+------------------+
               |                                     |
               v                                     v
     +-------------------+                 +-------------------+
     | PostgreSQL 16     |                 | Redis 7           |
     | (Primary Store)   |                 | (Cache / Sessions)|
     +-------------------+                 +-------------------+
```

Applications interact with GateKeeper exclusively through secure HTTP/REST APIs. GateKeeper is deployed as an autonomous service, avoiding tight coupling with client application runtimes.

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Web Framework | FastAPI | High-performance asynchronous REST API framework |
| Runtime & Language | Python 3.12+ | Core programming language |
| Database Engine | PostgreSQL 16 | ACID-compliant relational data persistence |
| Asynchronous ORM | SQLAlchemy 2.0 | Async data mapper and query builder |
| Schema Migrations | Alembic | Database schema version control and migration tracking |
| Fast Key-Value Cache | Redis 7 | Distributed session tracking and ephemeral key storage |
| Token Specification | JWT (python-jose) | Stateless access and stateful refresh token handling |
| Password Hashing | Passlib (Bcrypt) | Adaptive, salted cryptographic password hashing |
| Configuration | Pydantic Settings | Type-safe environment variable management |
| Testing Framework | Pytest (asyncio) | Automated asynchronous integration and unit testing |
| Static Analysis | Ruff | Python code formatting and linting |
| Orchestration | Docker Compose | Local and development service orchestration |

---

## Getting Started

### Prerequisites

- Python 3.12 or newer
- Docker and Docker Compose

### 1. Repository Setup

```bash
git clone https://github.com/your-username/gatekeeper.git
cd gatekeeper
```

### 2. Virtual Environment Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Environment Configuration

```bash
cp .env.example .env
```

Generate a secure secret key for JWT signing:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

Update `.env` with the generated secret key and environment-specific credentials.

### 4. Start Infrastructure

Launch the PostgreSQL and Redis containers:

```bash
docker compose up -d
```

### 5. Apply Database Migrations

```bash
alembic upgrade head
```

### 6. Run the API Server

```bash
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`.

- Interactive API Documentation: `http://localhost:8000/docs`
- Service Health Endpoint: `http://localhost:8000/health`

---

## Testing and Code Quality

Run test suites:

```bash
pytest tests/ -v
```

Execute code linting and formatting:

```bash
ruff check .
ruff format .
```

---

## Development Roadmap

- [ ] Phase 1: Project Foundation & Core Configuration
- [ ] Phase 2: User Registration & Authentication
- [ ] Phase 3: Session Management & Refresh Token Rotation
- [ ] Phase 4: Role-Based Access Control (RBAC)
- [ ] Phase 5: Email Verification & Password Reset Workflows
- [ ] Phase 6: Federated OAuth Providers (Google, GitHub)
- [ ] Phase 7: Multi-Factor Authentication (MFA / TOTP)
- [ ] Phase 8: Machine-to-Machine API Keys
- [ ] Phase 9: Audit Logging & Activity Tracking
- [ ] Phase 10: Administrative APIs & Management Console
- [ ] Phase 11: Security Hardening & Rate Limiting
- [ ] Phase 12: Production Deployment & Containerization

---

## License

MIT License. See LICENSE for details.
