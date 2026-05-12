import os
import json
import time
import socket
import random
import asyncio
import tempfile
import subprocess
import concurrent.futures
import requests
import base64

from urllib.parse import unquote

XRAY_BIN = "xray.exe" if os.name == "nt" else "xray"
XRAY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "xray_core",
    XRAY_BIN
)

MAX_XRAY_WORKERS = 5
FAST_TIMEOUT = 2
REAL_TIMEOUT = 3
BATCH_SIZE = 500

CACHE_FILE = "good_cache.json"
BLACKLIST_FILE = "dead_cache.json"

# =========================
# Utils
# =========================

def b64d(s):
    s = s.strip() + "=="
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except:
        try:
            return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
        except:
            return ""

# =========================
# Parse Links
# =========================

def extract_host_port(link):
    try:
        if "@" not in link:
            return None

        hp = link.split("@", 1)[1]

        if "?" in hp:
            hp = hp.split("?", 1)[0]

        if "#" in hp:
            hp = hp.split("#", 1)[0]

        host, port = hp.rsplit(":", 1)

        return host.strip(), int(port)

    except:
        return None

# =========================
# Async Fast Filter
# =========================

async def tcp_ping(host, port):

    try:
        fut = asyncio.open_connection(host, port)

        reader, writer = await asyncio.wait_for(
            fut,
            timeout=FAST_TIMEOUT
        )

        writer.close()

        try:
            await writer.wait_closed()
        except:
            pass

        return True

    except:
        return False

async def fast_filter(links):

    good = []

    sem = asyncio.Semaphore(100)

    async def worker(link):

        async with sem:

            hp = extract_host_port(link)

            if not hp:
                return

            host, port = hp

            ok = await tcp_ping(host, port)

            if ok:
                good.append(link)

    await asyncio.gather(*(worker(x) for x in links))

    return good

# =========================
# Xray Real Check
# =========================

def test_real_server(link, idx):

    port = 10000 + idx

    cfg = {
        "inbounds": [{
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
"outbounds": [parse_link(link)]
    }

    # هنا ضع parse الحقيقي الخاص بك
    # للحفاظ على طول الرد اختصرته
    # استبدل freedom بـ parse_link(link)

    try:

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            suffix=".json"
        ) as tf:

            json.dump(cfg, tf)

            cfg_path = tf.name

        proc = subprocess.Popen(
            [XRAY, "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        t1 = time.time()

        while time.time() - t1 < REAL_TIMEOUT:

            if proc.poll() is not None:
                break

            try:

                r = requests.get(
                    "https://www.google.com/generate_204",
                    proxies={
                        "http": f"socks5h://127.0.0.1:{port}",
                        "https": f"socks5h://127.0.0.1:{port}"
                    },
                    timeout=2
                )

                if r.status_code == 204:
                    return True

            except:
                pass

            time.sleep(0.2)

    except:
        return False

    finally:

        try:
            proc.kill()
        except:
            pass

        try:
            os.remove(cfg_path)
        except:
            pass

    return False

# =========================
# Cache
# =========================

def load_json(path):

    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def save_json(path, data):

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)

# =========================
# Main
# =========================

def main():

    print("[*] Loading config...")

    with open("remote_config.json", "r", encoding="utf-8") as f:
        conf = json.load(f)

    subs = conf.get("servers", [])

    links = []

    for sub in subs:

        try:

            r = requests.get(sub, timeout=8)

            if r.status_code != 200:
                continue

            txt = r.text.strip()

            if txt.startswith(("vmess://", "vless://")):
                lines = txt.splitlines()
            else:
                lines = b64d(txt).splitlines()

            for line in lines:

                line = line.strip()

                if line.startswith((
                    "vmess://",
                    "vless://",
                    "trojan://",
                    "hysteria2://",
                    "hy2://"
                )):
                    links.append(line)

        except:
            pass

    links = list(dict.fromkeys(links))

    print(f"[*] Total: {len(links)}")

    # =========================
    # Load cache
    # =========================

    cache = load_json(CACHE_FILE)
    dead = load_json(BLACKLIST_FILE)

    now = int(time.time())

    final_links = []

    for x in links:

        if x in dead:
            if now - dead[x] < 86400:
                continue

        final_links.append(x)

    random.shuffle(final_links)

    # =========================
    # FAST FILTER
    # =========================

    print("[*] Async filtering...")

    filtered = asyncio.run(fast_filter(final_links))

    print(f"[*] Fast alive: {len(filtered)}")

    # =========================
    # LIMIT
    # =========================

    filtered = filtered[:3000]

    print(f"[*] Real testing: {len(filtered)}")

    working = []

    # =========================
    # Batch processing
    # =========================

    for i in range(0, len(filtered), BATCH_SIZE):

        batch = filtered[i:i+BATCH_SIZE]

        print(f"[*] Batch {i} -> {i+len(batch)}")

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_XRAY_WORKERS
        ) as ex:

            futures = []

            for idx, link in enumerate(batch):

                futures.append(
                    ex.submit(test_real_server, link, idx)
                )

            for idx, fut in enumerate(futures):

                ok = fut.result()

                link = batch[idx]

                if ok:

                    working.append(link)

                    cache[link] = now

                else:

                    dead[link] = now

        time.sleep(5)

    # =========================
    # Save
    # =========================

    save_json(CACHE_FILE, cache)
    save_json(BLACKLIST_FILE, dead)

    working = list(dict.fromkeys(working))

    with open("working_servers.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(working))

    print(f"[+] Working: {len(working)}")

if __name__ == "__main__":
    main()
