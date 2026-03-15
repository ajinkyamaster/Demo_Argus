"""
Database bootstrap for Capsule Trust & Savings.
Run standalone to initialise or reset: python database.py
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capsule.db")


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("DROP TABLE IF EXISTS transactions")
    c.execute("DROP TABLE IF EXISTS users")

    c.executescript(
        """
        CREATE TABLE users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT NOT NULL UNIQUE,
            password  TEXT NOT NULL,
            email     TEXT NOT NULL,
            role      TEXT NOT NULL,
            ssn       TEXT NOT NULL,
            salary    INTEGER NOT NULL
        );

        CREATE TABLE transactions (
            tx_id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id           INTEGER NOT NULL REFERENCES users(id),
            amount            INTEGER NOT NULL,
            recipient_account TEXT NOT NULL,
            routing_number    TEXT NOT NULL,
            is_private        INTEGER NOT NULL DEFAULT 0
        );

        INSERT INTO users (id, username, password, email, role, ssn, salary)
        VALUES
            (1, 'j_sterling', 'Vault#2024!',   'j.sterling@capsule-trust.com', 'admin', '999-01-1234', 850000),
            (2, 's_miller',   'Fraud$ecure9',  's.miller@capsule-trust.com',   'staff', '999-05-6789', 120000),
            (3, 'm_thorne',   'Thorne@Bank1',  'm.thorne@capsule-trust.com',   'user',  '999-09-4321', 75000);

        INSERT INTO transactions (tx_id, user_id, amount, recipient_account, routing_number, is_private)
        VALUES
            (1, 1, 4500000, '8812-OFFSHORE-447', '021-000-021', 1);
        """
    )

    conn.commit()
    conn.close()
    print(f"Database initialised at {DB_PATH}")


if __name__ == "__main__":
    init_db()
