import json,base64,requests,time,subprocess,os,concurrent.futures,threading
from urllib.parse import unquote

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

def parse_link(link):
    if link.startswith("vmess://"): return parse_vmess(link)
    if link.startswith("vless://"): return parse_vless(link)
    if link.startswith("trojan://"): return parse_trojan(link)
    return None

def test_one(link, port):
    ob=parse_link(link)
    if not ob: return -1
    cfg={"inbounds":[{"port":port,"listen":"127.0.0.1","protocol":"socks","settings":{"udp":True}}],"outbounds":[ob]}
    cf=f"temp_{port}.json"
    with open(cf,"w") as f: json.dump(cfg,f)
    proc=subprocess.Popen([XRAY,"-c",cf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    lat=-1
    try:
        # Wait for Xray to start and try connecting
        for _ in range(3):
            time.sleep(1.0)
            if proc.poll() is not None: break # Xray crashed
            try:
                t=time.time()
                r=requests.get("https://www.google.com/generate_204",
                               proxies={"http":f"socks5h://127.0.0.1:{port}","https":f"socks5h://127.0.0.1:{port}"},
                               timeout=7)
                if r.status_code==204:
                    lat=int((time.time()-t)*1000)
                    break
            except: continue
    finally:
        proc.kill(); proc.wait()
        try: os.remove(cf)
        except: pass
    return lat


def main():
    print("[*] Reading remote_config.json...")
    with open("remote_config.json","r",encoding="utf-8") as f: conf=json.load(f)
    subs=conf.get("servers",[])
    links=[]
    for sub in subs:
        print(f"[*] Fetching: {sub[:80]}...")
        try:
            r=requests.get(sub,timeout=10)
            if r.status_code==200:
                txt=r.text.strip()
                if txt.startswith("vmess://") or txt.startswith("vless://") or txt.startswith("trojan://"):
                    lines=txt.splitlines()
                else:
                    try: lines=b64d(txt).splitlines()
                    except: lines=[]
                for l in lines:
                    l=l.strip()
                    if l.startswith(("vmess://","vless://","trojan://")):
                        links.append(l)
        except: pass
    
    links=list(dict.fromkeys(links))
    total=len(links)
    print(f"\n[*] Total unique links: {total}")
    print(f"[*] Starting multi-threaded test (20 workers)...\n")
    
    working=[]
    lock=threading.Lock()
    # Clear previous results
    with open("working_servers.txt","w",encoding="utf-8") as f: f.write("")
    
    def worker(idx_link):
        idx, link = idx_link
        port = 10810 + (idx % 1000) # Rotate ports to avoid collisions
        proto = link.split("://")[0].upper()
        lat = test_one(link, port)
        
        with lock:
            status = f"OK ({lat}ms)" if lat > 0 else "FAIL"
            print(f"[{idx+1}/{total}] {proto} {status}")
            if lat > 0:
                working.append(link)
                with open("working_servers.txt","a",encoding="utf-8") as f:
                    f.write(link+"\n")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(worker, enumerate(links))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Finalizing results...")
    
    print(f"\n{'='*50}")
    print(f"[*] Results: {len(working)} working servers found")
    if working:
        working = list(dict.fromkeys(working))
        with open("working_servers.txt","w",encoding="utf-8") as f:
            f.write("\n".join(working))
        sub_b64=base64.b64encode("\n".join(working).encode()).decode()
        with open("clean_sub.txt","w",encoding="utf-8") as f:
            f.write(sub_b64)
        print(f"[+] Finalized {len(working)} servers to working_servers.txt")
        print(f"[+] Saved Base64 subscription to clean_sub.txt")
    else:
        print("[-] No working servers found.")

if __name__=="__main__":
    main()
