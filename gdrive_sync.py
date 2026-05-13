import os
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# Google Drive File ID
FILE_ID = '17nELFayxeBqL-Hw69DX9cJtD0Fl6JPl9'

def sync_to_drive():
    # Get credentials from GitHub environment variable
    creds_json = os.environ.get('GDRIVE_SERVICE_ACCOUNT')
    if not creds_json:
        print("[-] Error: GDRIVE_SERVICE_ACCOUNT secret not found!")
        return

    try:
        service_info = json.loads(creds_json)
        creds = service_account.Credentials.from_service_account_info(service_info)
        service = build('drive', 'v3', credentials=creds, cache_discovery=False)

        local_file = 'clean_sub.txt'
        if not os.path.exists(local_file):
            print(f"[-] Error: {local_file} not found!")
            return

        print(f"[*] Updating Google Drive file (ID: {FILE_ID})...")
        
        # Use resumable=False for faster uploads of small text files
        media = MediaFileUpload(local_file, mimetype='text/plain', resumable=False)
        
        updated_file = service.files().update(
            fileId=FILE_ID,
            media_body=media
        ).execute()

        print(f"[+] Success! Google Drive file updated. File ID: {updated_file.get('id')}")

    except Exception as e:
        print(f"[-] Error syncing to Google Drive: {e}")

if __name__ == "__main__":
    sync_to_drive()
