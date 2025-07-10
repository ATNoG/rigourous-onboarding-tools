import requests

from apis.openslice import OpenSlice

class Auth(OpenSlice):
    AUTH_URL = "/auth/realms/openslice/protocol/openid-connect"

    def __init__(self, url: str):
        super().__init__(url)
        self._url += self.AUTH_URL

    def get_token(self) -> str:
        try:
            response = requests.post(self._url + "/token", 
                                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                                    data={
                                        "username": "admin", 
                                        "password": "admin", 
                                        "grant_type": "password",
                                        "client_id": "osapiWebClientId"
                                    },
                                    timeout=5)
            if response.status_code != requests.codes.ok:
                super().handle_response_not_ok(response)
            return response.json()["access_token"]
        except requests.RequestException:
            return ""
