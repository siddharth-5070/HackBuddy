import requests
import random
import time

class VPNManager:
    """
    Manages VPN / Proxy routing to prevent tracking of the application.
    Fetches open free proxy servers to anonymize outbound HTTP requests.
    """
    def __init__(self):
        self.proxies = []
        self._fetch_free_proxies()

    def _fetch_free_proxies(self):
        """Fetches a list of free public proxies via an open API."""
        print("[*] VPNManager: Fetching free proxy servers...")
        try:
            # Using Geonode free proxy list API. We look for protocols http, https
            res = requests.get(
                'https://proxylist.geonode.com/api/proxy-list?limit=50&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps',
                timeout=10
            )
            if res.status_code == 200:
                data = res.json().get('data', [])
                for proxy in data:
                    ip = proxy.get('ip')
                    port = proxy.get('port')
                    protocols = proxy.get('protocols', ['http'])
                    if ip and port:
                        proto = "https" if "https" in protocols else "http"
                        self.proxies.append(f"{proto}://{ip}:{port}")
                
                print(f"[*] VPNManager: Fetched {len(self.proxies)} functional proxies.")
            else:
                print(f"[-] VPNManager: Failed to fetch proxies. Status Code: {res.status_code}")
        except Exception as e:
            print(f"[-] VPNManager: Error fetching proxies: {e}")

    def get_proxy(self):
        """Returns a random proxy from the available pool."""
        if not self.proxies:
            return None
            
        proxy_url = random.choice(self.proxies)
        return {
            "http": proxy_url,
            "https": proxy_url
        }
    
    def apply_to_session(self, session: requests.Session):
        """
        Applies a random proxy to the provided requests Session.
        Returns the applied proxy dict, or None if failed.
        """
        proxy = self.get_proxy()
        if proxy:
            session.proxies.update(proxy)
            print(f"[*] VPNManager: Session routed through proxy: {proxy['http']}")
            return proxy
        else:
            print("[-] VPNManager: No proxy available. Direct connection used.")
            return None
