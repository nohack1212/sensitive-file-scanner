import requests
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# CONFIG
INPUT_FILE = "target.txt"  # fichier contenant les sous-domaines (ex: sub.domain.com)
KEYWORDS = [
    "phpinfo.php", ".env", "config.php", "config.json", "database.sql",
    "dump.sql", "backup.zip", "backup.sql", "database.sql.gz", "database.sql.zip",
    ".sql", ".log", ".bak", ".old", "id_rsa", "id_rsa.pub", "authorized_keys",
    ".htpasswd", "docker-compose.yml", "dockerfile", "credentials.json", "secret",
    "secrets.yaml", ".key", ".pem", ".crt", ".pfx", ".p12", ".git/config",
    ".git-credentials", ".svn/entries", "config.ini", "settings.py",
    "local.settings.json", ".DS_Store", ".vscode/sftp.json", ".apikey.json"
]
MAX_THREADS = 10
TIMEOUT = 5

def check_url(url):
    try:
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        if response.status_code == 200:
            requested = urllib.parse.urlparse(url)
            final = urllib.parse.urlparse(response.url)

            if requested.netloc == final.netloc:
                if final.path.rstrip('/') == requested.path.rstrip('/') or \
                   final.path.rstrip('/').startswith(requested.path.rstrip('/') + '/'):
                    return url
    except requests.RequestException:
        pass
    return None

def check_keywords_on_subdomains(subdomains):
    found_by_host = defaultdict(list)
    urls_to_check = [f"http://{sub.rstrip('/')}/{keyword}" for sub in subdomains for keyword in KEYWORDS]

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_url, url): url for url in urls_to_check}
        for future in as_completed(futures):
            result = future.result()
            if result:
                host = urllib.parse.urlparse(result).hostname
                found_by_host[host].append(result)

    # Ne garder que les hôtes avec < 5 fichiers détectés (éviter faux positifs massifs)
    filtered_results = []
    for host, urls in found_by_host.items():
        if len(urls) < 5:
            filtered_results.extend(urls)
        else:
            print(f"[~] Trop de fichiers trouvés sur {host} ({len(urls)}), ignoré.")

    return filtered_results

def main():
    try:
        with open(INPUT_FILE, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Fichier non trouvé : {INPUT_FILE}")
        return

    print(f"[+] Analyse de {len(subdomains)} sous-domaines...\n")
    found = check_keywords_on_subdomains(subdomains)

    if found:
        for url in found:
            print(f"[!] Fichier sensible trouvé : {url}")
    else:
        print("[-] Aucun fichier sensible détecté.")

if __name__ == "__main__":
    main()
