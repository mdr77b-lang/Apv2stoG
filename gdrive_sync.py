import os
import json
import hashlib

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

FILE_ID = '17nELFayxeBqL-Hw69DX9cJtD0Fl6JPl9'

CACHE_HASH_FILE = ".last_upload_hash"

def file_hash(path):

    h = hashlib.sha256()

    with open(path, "rb") as f:

        while True:

            chunk = f.read(8192)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()

def sync_to_drive():

    creds_json = os.environ.get('GDRIVE_SERVICE_ACCOUNT')

    if not creds_json:
        print("[-] Missing GDRIVE_SERVICE_ACCOUNT")
        return

    local_file = "clean_sub.txt"

    if not os.path.exists(local_file):
        print("[-] clean_sub.txt not found")
        return

    # =========================
    # Compare hash
    # =========================

    new_hash = file_hash(local_file)

    old_hash = None

    if os.path.exists(CACHE_HASH_FILE):

        try:

            with open(CACHE_HASH_FILE, "r") as f:
                old_hash = f.read().strip()

        except:
            pass

    if new_hash == old_hash:
        print("[*] No changes detected. Skip upload.")
        return

    try:

        service_info = json.loads(creds_json)

        creds = service_account.Credentials.from_service_account_info(
            service_info
        )

        service = build(
            "drive",
            "v3",
            credentials=creds,
            cache_discovery=False
        )

        print("[*] Uploading updated file...")

        media = MediaFileUpload(
            local_file,
            mimetype="text/plain",
            resumable=False
        )

        updated = service.files().update(
            fileId=FILE_ID,
            media_body=media
        ).execute()

        print(f"[+] Uploaded successfully: {updated.get('id')}")

        with open(CACHE_HASH_FILE, "w") as f:
            f.write(new_hash)

    except Exception as e:

        print(f"[-] Upload failed: {e}")

if __name__ == "__main__":
    sync_to_drive()
