import requests

DEFAULT_TIMEOUT = 5


class PolicyClient:
    def __init__(self, server_url, hostname, api_token=""):
        self.server_url = server_url.rstrip("/")
        self.hostname = hostname
        self.api_token = api_token

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_token}"}

    def register(self, enrollment_key, os_info=None, username=None, agent_version="1.0.0"):
        url = f"{self.server_url}/agent_register.php"
        payload = {"hostname": self.hostname, "enrollment_key": enrollment_key,
                   "os_info": os_info, "username": username, "agent_version": agent_version}
        try:
            resp = requests.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 409:
                print("[policy_client] Hostname da dang ky roi. Dien lai api_token cu vao config.ini.")
                return None
            resp.raise_for_status()
            data = resp.json()
            self.api_token = data.get("api_token", "")
            return data
        except requests.RequestException as e:
            print(f"[policy_client] Loi register: {e}")
            return None

    def get_policy(self):
        url = f"{self.server_url}/agent_policy.php"
        try:
            resp = requests.get(url, params={"hostname": self.hostname},
                                 headers=self._headers(), timeout=DEFAULT_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            print(f"[policy_client] Loi lay policy: {e}")
            return None

    def send_heartbeat(self, agent_version="1.0.0"):
        url = f"{self.server_url}/agent_heartbeat.php"
        try:
            resp = requests.post(url, json={"hostname": self.hostname, "agent_version": agent_version},
                                  headers=self._headers(), timeout=DEFAULT_TIMEOUT)
            resp.raise_for_status()
            return True
        except requests.RequestException as e:
            print(f"[policy_client] Loi heartbeat: {e}")
            return False

    def send_report(self, event):
        url = f"{self.server_url}/agent_report.php"
        try:
            resp = requests.post(url, json=event, headers=self._headers(), timeout=DEFAULT_TIMEOUT)
            resp.raise_for_status()
            return True
        except requests.RequestException as e:
            print(f"[policy_client] Loi report: {e}")
            return False
