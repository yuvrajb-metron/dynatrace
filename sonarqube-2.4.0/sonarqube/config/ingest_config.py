class IngestConfig:
    def __init__(self, security_events_endpoint: str, sdlc_events_endpoint: str, token: str):
        self.security_events_endpoint = security_events_endpoint
        self.sdlc_events_endpoint = sdlc_events_endpoint
        self.token = token

    def get_headers_with_api_token_and_plain_text(self):
        return {"Authorization": f"Api-Token {self.token}", "Content-Type": "text/plain"}

    def get_headers_with_api_token(self):
        return {"Authorization": f"Api-Token {self.token}", "Content-Type": "application/json"}

    def ingest_security_event_endpoint(self):
        return self.security_events_endpoint

    def ingest_sdlc_endpoint(self):
        return self.sdlc_events_endpoint
