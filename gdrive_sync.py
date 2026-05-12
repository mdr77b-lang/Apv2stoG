import os
import json
import sys
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# معرف الملف على جوجل درايف (الذي أرسلته)
FILE_ID = '17nELFayxeBqL-Hw69DX9cJtD0Fl6JPl9'

def sync_to_drive():
    # الحصول على بيانات الاعتماد من GitHub Secrets
    creds_json = os.environ.get('GDRIVE_SERVICE_ACCOUNT')
    if not creds_json:
        print("[-] Error: GDRIVE_SERVICE_ACCOUNT secret not found!")
        return

    try:
        service_info = json.loads(creds_json)
        creds = service_account.Credentials.from_service_account_info(service_info)
        service = build('drive', 'v3', credentials=creds)

        # الملف المحلي المراد رفعه
        local_file = 'clean_sub.txt'
        if not os.path.exists(local_file):
            print(f"[-] Error: {local_file} not found!")
            return

        print(f"[*] Updating Google Drive file (ID: {FILE_ID})...")
        
        media = MediaFileUpload(local_file, mimetype='text/plain', resumable=True)
        updated_file = service.files().update(
            fileId=FILE_ID,
            media_body=media
        ).execute()

        print(f"[+] Success! Google Drive file updated. File ID: {updated_file.get('id')}")

    except Exception as e:
        print(f"[-] Error syncing to Google Drive: {e}")

if __name__ == "__main__":
    sync_to_drive()
