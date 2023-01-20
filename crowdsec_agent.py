import requests
from datetime import datetime, timezone


class CrowdsecAgent:
    def __init__(self, api_url, login, password):
        self.api_url = api_url
        self.__login = login
        self.__password = password
        self.__token = None

    def __do_login(self):
        jsonBody = {
            "machine_id": self.__login,
            "password": self.__password,
            "scenarios": ["useless"], # CS LAPI needs a scenario at login, unused
        }
        r = requests.post(self.api_url + "/v1/watchers/login", json=jsonBody)
        if r.status_code == 200:
            self.__token = r.json()["token"]
        else:
            raise Exception("Error while logging in")

    def push_alert(self, source_ip, scenario="", message=""):
        if not self.__token:
            self.__do_login()

        jsonBody = [
            {
                "scenario": scenario,
                "scenario_hash": "",
                "scenario_version": "",
                "simulated": False,
                "message": message,
                "start_at": datetime.now(timezone.utc).isoformat(),
                "stop_at": datetime.now(timezone.utc).isoformat(),
                "remediation": True,
                "capacity": 0,
                "leakspeed": "0",
                "source": {
                    "scope": "Ip",
                    "value": source_ip,
                    "ip": source_ip,
                },
                "events": [],
                "events_count": 1,
                "meta": [{"key": "source", "value": "flask-rate-limit"}],
            }
        ]

        r = requests.post(
            self.api_url + "/v1/alerts",
            json=jsonBody,
            headers={"Authorization": "Bearer " + self.__token},
        )

        if not (r.status_code >= 200 and r.status_code < 300):
            print("Error while pushing alert: " + r.text + " -- " + str(r.status_code))
