# Auth Core

Auth Core is a reusable PostgreSQL authentication and authorization database
designed to be used as the foundation for multiple applications.

It provides:
- Centralised user management
- Role-based access control (RBAC)
- Secure privilege separation
- A standard schema that can be reused across projects

---

## Features

- Users table with secure design
- Roles and permissions model
- Designed for enterprise-style applications
- Can be extended per application without modifying core tables

---

## Database

- Engine: PostgreSQL
- Core file: `auth_core.sql`

To load the database:

```bash
psql -U postgres -d your_database_name -f auth_core.sql
