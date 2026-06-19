import json,base64,requests,time,subprocess,os,concurrent.futures,threading
from urllib.parse import unquote, quote

XRAY_BIN = "xray.exe" if os.name == 'nt' else "xray"
XRAY=os.path.join(os.path.dirname(os.path.abspath(__file__)),"xray_core",XRAY_BIN)

def b64d(s):
    s=s.strip()+'=='
    try: return base64.b64decode(s).decode('utf-8',errors='ignore')
    except:
        try: return base64.urlsafe_b64decode(s).decode('utf-8',errors='ignore')
        except: return ""

def parse_vmess(link):
    try:
        d=json.loads(b64d(link[8:]))
        net=d.get("net","tcp")
        obj={
            "protocol":"vmess",
            "settings":{"vnext":[{"address":d["add"],"port":int(d.get("port",443)),"users":[{"id":d["id"],"alterId":int(d.get("aid",0)),"security":"auto"}]}]},
            "streamSettings":{"network":net}
        }
        if d.get("tls")=="tls":
            obj["streamSettings"]["security"]="tls"
            obj["streamSettings"]["tlsSettings"]={"serverName":d.get("sni") or d.get("host") or d["add"],"allowInsecure":True}
        if net=="ws":
            obj["streamSettings"]["wsSettings"]={"path":d.get("path","/"),"headers":{"Host":d.get("host","")}}
        elif net=="grpc":
            obj["streamSettings"]["grpcSettings"]={"serviceName":d.get("path","")}
        return obj
    except: return None

def parse_vless(link):
    try:
        r=link[8:]
        if '#' in r: r=r.rsplit('#',1)[0]
        uid,hp=r.split('@',1)
        if '?' in hp: ap,qs=hp.split('?',1)
        else: ap,qs=hp,''
        ps=ap.rsplit(':',1)
        addr,port=ps[0],int(ps[1]) if len(ps)>1 else 443
        pm=dict(x.split('=',1) for x in qs.split('&') if '=' in x) if qs else {}
        net=pm.get('type','tcp'); sec=pm.get('security','none')
        sni=pm.get('sni',''); fp=pm.get('fp','')
        ob={"protocol":"vless","settings":{"vnext":[{"address":addr,"port":port,"users":[{"id":uid,"encryption":"none"}]}]},"streamSettings":{"network":net}}
        fl=pm.get('flow','')
        if fl: ob["settings"]["vnext"][0]["users"][0]["flow"]=fl
        if sec=="tls":
            ob["streamSettings"]["security"]="tls"
            ob["streamSettings"]["tlsSettings"]={"serverName":sni or addr,"allowInsecure":True}
            if fp: ob["streamSettings"]["tlsSettings"]["fingerprint"]=fp
        elif sec=="reality":
            ob["streamSettings"]["security"]="reality"
            rs={"serverName":sni or addr,"show":False}
            if fp: rs["fingerprint"]=fp
            if pm.get('pbk'): rs["publicKey"]=pm["pbk"]
            if pm.get('sid'): rs["shortId"]=pm["sid"]
            ob["streamSettings"]["realitySettings"]=rs
        if net=="ws":
            h=pm.get('host','')
            ob["streamSettings"]["wsSettings"]={"path":unquote(pm.get('path','/')),"headers":{"Host":h} if h else {}}
        elif net=="grpc":
            ob["streamSettings"]["grpcSettings"]={"serviceName":pm.get('serviceName','')}
        return ob
    except: return None

def parse_trojan(link):
    try:
        r=link[9:]
        if '#' in r: r=r.rsplit('#',1)[0]
        pw,hp=r.split('@',1)
        if '?' in hp: ap,qs=hp.split('?',1)
        else: ap,qs=hp,''
        ps=ap.rsplit(':',1)
        addr,port=ps[0],int(ps[1]) if len(ps)>1 else 443
        pm=dict(x.split('=',1) for x in qs.split('&') if '=' in x) if qs else {}
        net=pm.get('type','tcp')
        ob={
            "protocol":"trojan",
            "settings":{"servers":[{"address":addr,"port":port,"password":unquote(pw)}]},
            "streamSettings":{"network":net,"security":"tls","tlsSettings":{"serverName":pm.get('sni') or addr,"allowInsecure":True}}
        }
        if net=="ws":
            ob["streamSettings"]["wsSettings"]={"path":unquote(pm.get('path','/')),"headers":{"Host":pm.get('host','')}}
        elif net=="grpc":
            ob["streamSettings"]["grpcSettings"]={"serviceName":pm.get('serviceName','')}
        return ob
    except: return None

def parse_hysteria2(link):
    try:
        prefix = "hysteria2://" if link.startswith("hysteria2://") else "hy2://"
        r = link[len(prefix):]
        if '#' in r: r = r.rsplit('#', 1)[0]
        auth, hp = r.split('@', 1)
        if '?' in hp: ap, qs = hp.split('?', 1)
        else: ap, qs = hp, ''
        ps = ap.rsplit(':', 1)
        addr, port = ps[0], int(ps[1]) if len(ps) > 1 else 443
        pm = dict(x.split('=', 1) for x in qs.split('&') if '=' in x) if qs else {}
        
        ob = {
            "protocol": "hysteria",
            "settings": {
                "version": 2,
                "address": addr,
                "port": port
            },
            "streamSettings": {
                "network": "hysteria",
                "security": "tls",
                "tlsSettings": {
                    "serverName": pm.get('sni') or addr,
                    "allowInsecure": pm.get('insecure') in ['1', 'true'],
                    "alpn": ["h3"]
                },
                "hysteriaSettings": {
                    "version": 2,
                    "auth": unquote(auth)
                }
            }
        }
        
        obfs = pm.get('obfs')
        obfs_pw = pm.get('obfs-password')
        if obfs and obfs != "none":
            ob["streamSettings"]["hysteriaSettings"]["obfuscation"] = {
                "type": obfs,
                "password": obfs_pw or ""
            }
        return ob
    except: return None

def parse_shadowsocks(link):
    try:
        r = link[5:]
        if '#' in r: r = r.rsplit('#', 1)[0]
        # Some links are fully base64 encoded after ss://, others only userinfo
        if '@' not in r:
            try:
                decoded = b64d(r)
                if '@' in decoded: r = decoded
            except: pass
            
        if '@' in r:
            userinfo, hp = r.rsplit('@', 1)
            if ':' not in userinfo:
                userinfo = b64d(userinfo)
            
            if ':' not in userinfo: return None
            method, password = userinfo.split(':', 1)
            
            if '?' in hp: hp = hp.split('?', 1)[0]
            ps = hp.rsplit(':', 1)
            addr, port = ps[0], int(ps[1])
            
            return {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{"address": addr, "port": port, "method": method, "password": password}]
                }
            }
    except: pass
    return None

def parse_link(link):
    if link.startswith("vmess://"): return parse_vmess(link)
    if link.startswith("vless://"): return parse_vless(link)
    if link.startswith("trojan://"): return parse_trojan(link)
    if link.startswith("ss://"): return parse_shadowsocks(link)
    if link.startswith(("hysteria2://", "hy2://")): return parse_hysteria2(link)
    return None

def rename_link(link, new_name):
    try:
        if link.startswith("vmess://"):
            b64_str = link[8:]
            decoded = b64d(b64_str)
            d = json.loads(decoded)
            d["ps"] = new_name
            json_str = json.dumps(d)
            b64_encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
            return f"vmess://{b64_encoded}"
        else:
            if "#" in link:
                base = link.split("#", 1)[0]
            else:
                base = link
            return f"{base}#{quote(new_name)}"
    except:
        return link

def test_one(link, port):
    ob=parse_link(link)
    if not ob: return -1
    cfg={"inbounds":[{"port":port,"listen":"127.0.0.1","protocol":"socks","settings":{"udp":True}}],"outbounds":[ob]}
    cf=f"temp_{port}.json"
    with open(cf,"w") as f: json.dump(cfg,f)
    proc=subprocess.Popen([XRAY,"-c",cf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    lat=-1
    try:
        # High Accuracy Check: Double Verification (Google + Cloudflare)
        # We try up to 4 times to let Xray core initialize properly
        for _ in range(4):
            if proc.poll() is not None: break
            try:
                t_req = time.time()
                # 1st Check: Google Connectivity
                r1 = requests.get("https://www.google.com/generate_204",
                                proxies={"http":f"socks5h://127.0.0.1:{port}","https":f"socks5h://127.0.0.1:{port}"},
                                timeout=5)
                if r1.status_code == 204:
                    lat_val = int((time.time() - t_req) * 1000)
                    
                    # 2nd Check: Cloudflare (Confirming real routing and stability)
                    try:
                        r2 = requests.get("https://1.1.1.1/cdn-cgi/trace",
                                        proxies={"http":f"socks5h://127.0.0.1:{port}","https":f"socks5h://127.0.0.1:{port}"},
                                        timeout=4)
                        if "ip=" in r2.text:
                            lat = lat_val
                            break # Confirmed working!
                    except:
                        continue # Failed second check, retry
            except:
                time.sleep(0.5)
                continue
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except:
            proc.kill()
        try: os.remove(cf)
        except: pass
    
    # Accuracy Filter: Discard unusable or extremely slow servers (> 5s)
    if lat > 5000: return -1
    return lat

def main():
    print("[!!!] Starting V2Ray Tester V3...")
    
    # Priority 1: Read from Environment Variable (GitHub Secrets)
    config_str = os.environ.get("APP_CONFIG_JSON")
    conf = {}
    if config_str:
        try:
            conf = json.loads(config_str)
            print("[+] Loaded configuration from APP_CONFIG_JSON secret.")
        except Exception as e:
            print(f"[-] Error parsing APP_CONFIG_JSON secret: {e}")
    
    # Priority 2: Fallback to local file (for local testing)
    if not conf:
        if os.path.exists("remote_config.json"):
            with open("remote_config.json","r",encoding="utf-8") as f: 
                conf=json.load(f)
                print("[+] Loaded configuration from remote_config.json.")
        else:
            print("[!] Warning: No configuration found in environment or local file.")
            conf = {"servers": []}

    subs = conf.get("servers", [])
    links = []

    # Fetch from subscriptions
    for i, sub in enumerate(subs, 1):
        print(f"[*] Fetching subscription {i}/{len(subs)}...")
        try:
            r=requests.get(sub,timeout=10)
            if r.status_code==200:
                txt=r.text.strip()
                if any(txt.startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "hy2://"]):
                    lines=txt.splitlines()
                else:
                    try: lines=b64d(txt).splitlines()
                    except: lines=[]
                for l in lines:
                    l=l.strip()
                    if l.startswith(("vmess://","vless://","trojan://","ss://","hysteria2://","hy2://")):
                        links.append(l)
        except Exception as e:
            print(f"[-] Error fetching {sub[:30]}: {e}")
    
    # Priority 3: Add Raw Links from Secret (if any)
    raw_links_str = os.environ.get("APP_RAW_LINKS")
    if raw_links_str:
        print("[+] Adding raw links from APP_RAW_LINKS secret.")
        links.extend(raw_links_str.splitlines())
    
    links=list(dict.fromkeys(links))
    total=len(links)
    print(f"\n[*] Total unique links: {total}")
    print(f"[*] Starting high-accuracy test (20 workers)...\n")
    
    working=[]
    lock=threading.Lock()
    # Clear previous results
    with open("working_servers.txt","w",encoding="utf-8") as f: f.write("")
    
    def worker(idx_link):
        idx, link = idx_link
        port = 10810 + (idx % 1000)
        proto = link.split("://")[0].upper()
        lat = test_one(link, port)
        
        with lock:
            status = f"OK ({lat}ms)" if lat > 0 else "FAIL"
            print(f"[{idx+1}/{total}] {proto} {status}")
            if lat > 0:
                renamed = rename_link(link, "V2Ray Server Store")
                working.append(renamed)
                with open("working_servers.txt","a",encoding="utf-8") as f:
                    f.write(renamed+"\n")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(worker, enumerate(links))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Finalizing results...")
    
    print(f"\n{'='*50}")
    print(f"[*] Results: {len(working)} working servers found")
    if working:
        working = list(dict.fromkeys(working))
        # Optional: sort by something if needed
        with open("working_servers.txt","w",encoding="utf-8") as f:
            f.write("\n".join(working))
        sub_b64=base64.b64encode("\n".join(working).encode()).decode()
        with open("clean_sub.txt","w",encoding="utf-8") as f:
            f.write(sub_b64)
        print(f"[+] Finalized {len(working)} high-accuracy servers to working_servers.txt")
        print(f"[+] Saved Base64 subscription to clean_sub.txt")
    else:
        print("[-] No working servers found.")

if __name__=="__main__":
    main()
