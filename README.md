# 🔐 GateKeeper

**A production-ready Identity and Access Management (IAM) platform built with FastAPI.**

GateKeeper is a standalone authentication and authorization service designed to be integrated with multiple applications — similar to Auth0, Keycloak, or Clerk, but built from scratch for learning and portfolio purposes.

---

## Architecture

```text
Frontend App          Mobile App          Admin Dashboard
     │                    │                     │
     ▼                    ▼                     ▼
Application Backend   Application Backend   Application Backend
     │                    │                     │
     └────────────────────┼─────────────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │  GateKeeper  │
                   │   IAM API    │
                   └──────┬───────┘
                          │
                   ┌──────┴───────┐
                   │              │
                   ▼              ▼
              PostgreSQL       Redis
```

Applications communicate with GateKeeper through REST APIs. GateKeeper is **not** embedded inside your app — it runs as an independent service.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | FastAPI |
| Database | PostgreSQL 16 |
| ORM | SQLAlchemy 2.0 (async) |
| Migrations | Alembic |
| Cache/Sessions | Redis 7 |
| Auth | JWT (python-jose), OAuth2 |
| Task Queue | Celery |
| Containerization | Docker & Docker Compose |
| Configuration | Pydantic Settings |
| Testing | Pytest (async) |
| Linting | Ruff |
| CI/CD | GitHub Actions |

---

## Getting Started

### Prerequisites

- Python 3.12+
- Docker & Docker Compose

### 1. Clone the repository

```bash
git clone https://github.com/your-username/gatekeeper.git
cd gatekeeper
```

### 2. Set up Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env and set a strong SECRET_KEY:
# python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

### 4. Start infrastructure

```bash
docker compose up -d
```

This starts PostgreSQL and Redis locally.

### 5. Run database migrations

```bash
alembic upgrade head
```

### 6. Start the development server

```bash
uvicorn app.main:app --reload
```

The API is now running at [http://localhost:8000](http://localhost:8000)

- **API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs) (debug mode only)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

## Development

### Run tests

```bash
pytest tests/ -v
```

### Lint & format

```bash
ruff check app/ tests/
ruff format app/ tests/
```

---

## Project Status

🚧 **Under active development**

- [x] Phase 1: Project Foundation & Configuration
- [ ] Phase 2: User Registration & Authentication
- [ ] Phase 3: Session Management
- [ ] Phase 4: Authorization (RBAC)
- [ ] Phase 5: Email Verification & Password Reset
- [ ] Phase 6: OAuth (Google, GitHub)
- [ ] Phase 7: Multi-Factor Authentication
- [ ] Phase 8: API Keys
- [ ] Phase 9: Audit Logs
- [ ] Phase 10: Admin APIs
- [ ] Phase 11: Security Hardening
- [ ] Phase 12: Production Deployment

---

## License

MIT
