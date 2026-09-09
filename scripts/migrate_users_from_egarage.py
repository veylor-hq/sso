"""
Migrate users from eGarage (velo_db.user) to Veylor SSO (veylor_sso.users).
"""
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pymongo import MongoClient

ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def generate_opaque_id(prefix: str = "usr") -> str:
    timestamp_ms = int(time.time() * 1000)
    time_chars = []
    for _ in range(10):
        time_chars.append(ENCODING[timestamp_ms & 0x1F])
        timestamp_ms >>= 5
    time_part = "".join(reversed(time_chars))
    rand_chars = "".join(secrets.choice(ENCODING) for _ in range(16))
    return f"{prefix}_{time_part}{rand_chars}"


def run_migration(mongo_uri: str = "mongodb://velo-api-mongo:27017"):
    client = MongoClient(mongo_uri)
    velo_db = client["velo_db"]
    sso_db = client["veylor_sso"]

    velo_users = list(velo_db["user"].find({}))
    print(f"Found {len(velo_users)} users in velo_db.user")

    # Clear out existing test records in SSO as requested
    del_res = sso_db["users"].delete_many({})
    print(f"Cleared {del_res.deleted_count} existing test records in veylor_sso.users")

    migrated = 0
    for u in velo_users:
        email = u["email"].strip().lower()
        first_name = (u.get("first_name") or "").strip()
        last_name = (u.get("last_name") or "").strip()
        name = f"{first_name} {last_name}".strip() or u.get("username") or email.split("@")[0]

        sso_id = generate_opaque_id("usr")
        created_at = u.get("created_at") or datetime.now(timezone.utc)
        if hasattr(created_at, "tzinfo") and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        sso_user = {
            "_id": sso_id,
            "id": sso_id,
            "email": email,
            "email_verified": bool(u.get("email_verified", False)),
            "password_hash": u["password"],
            "name": name,
            "given_name": first_name or None,
            "family_name": last_name or None,
            "avatar_url": u.get("avatar_url"),
            "disabled": False,
            "created_at": created_at,
            "updated_at": datetime.now(timezone.utc),
            "last_login_at": None,
            "auth_provider": "local",
            "google_sub": None,
        }

        sso_db["users"].insert_one(sso_user)

        # Update velo_db with sso_id link
        velo_db["user"].update_one(
            {"_id": u["_id"]},
            {"$set": {"sso_id": sso_id}}
        )

        print(f"  [+] Migrated {email} -> {sso_id} ({name})")
        migrated += 1

    print(f"\nSuccessfully migrated {migrated} users to veylor_sso.users!")


if __name__ == "__main__":
    uri = sys.argv[1] if len(sys.argv) > 1 else os.getenv("MONGODB_URL", "mongodb://velo-api-mongo:27017")
    run_migration(uri)
