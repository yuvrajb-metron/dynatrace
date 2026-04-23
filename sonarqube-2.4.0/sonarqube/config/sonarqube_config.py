from urllib import parse

from sonarqube.utils.constants import METRIC_ID_LOOKUP, METRIC_ID_LOOKUP_MQR
from sonarqube.utils.time import normalize_datetime
from sonarqube.utils.url_util import ensure_trailing_slash


class SonarQubeConfig:
    def __init__(
        self,
        url: str,
        token: str,
        verify: bool | str,
        cloud: bool,
        org: None | str = None,
        proxy: None | str = None,
    ):
        self.url = ensure_trailing_slash(url)
        self.token = token
        self.verify = verify
        self.cloud = cloud
        self.org = org
        self.proxy = proxy

    @classmethod
    def get_v2_api_url(cls, url: str) -> str:
        split_url = url.split("https://")
        return f"https://api.{split_url[1]}"

    def get_headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def get_proxies(self) -> dict | None:
        if self.proxy:
            return {"https": self.proxy}
        return None

    def get_component_endpoint(self, component: str):
        params = {"component": component}
        encoded_params = parse.urlencode(params)
        return f"{self.url}api/components/show?{encoded_params}"

    def get_components_endpoint(self):
        params = {"qualifiers": "TRK"}
        if self.cloud:
            params["organization"] = self.org
        encoded_params = parse.urlencode(params)
        return f"{self.url}api/components/search?{encoded_params}"

    def get_component_tree_endpoint(self, component: str):
        params = {"component": component, "qualifiers": "FIL,UTS"}
        encoded_params = parse.urlencode(params)
        return f"{self.url}api/components/tree?{encoded_params}"

    def get_analysis_endpoint(self, component: str, from_date: str):
        params = {"project": component, "from": normalize_datetime(from_date)}
        encoded_params = parse.urlencode(params)
        return f"{self.url}api/project_analyses/search?{encoded_params}"

    def get_issues_endpoint(self, component: str, severities: str, created_at: str):
        params = {
            "createdBefore": normalize_datetime(created_at),
            "impactSeverities": severities,
            "issueStatuses": "OPEN,CONFIRMED",
            "types": "VULNERABILITY",
            "facets": (
                "severities,statuses,rules,author,tags,owaspTop10,cwe,"
                "createdAt,impactSoftwareQualities,impactSeverities"
            ),
        }
        if self.cloud:
            params["componentKeys"] = component
        else:
            params["components"] = component
        encoded_params = parse.urlencode(params)

        return f"{self.url}api/issues/search?{encoded_params}"

    def get_metrics_endpoint(self, component: str):
        params = {
            "component": component,
            "metricKeys": ",".join(METRIC_ID_LOOKUP.keys()),
        }
        encoded_params = parse.urlencode(params)
        return f"{self.url}api/measures/component?{encoded_params}"

    def get_metrics_endpoint_mqr(self, component: str):
        params = {
            "component": component,
            "metricKeys": ",".join({**METRIC_ID_LOOKUP, **METRIC_ID_LOOKUP_MQR}.keys()),
        }
        encoded_params = parse.urlencode(params)
        return f"{self.url}api/measures/component?{encoded_params}"

    def get_binding_endpoint(self, component: str):
        params = {"project": component}
        encoded_params = parse.urlencode(params)
        return f"{self.url}api/alm_settings/get_binding?{encoded_params}"

    def get_rule_endpoint(self, rule: str):
        params = {"key": rule}
        if self.cloud:
            params["organization"] = self.org
        encoded_params = parse.urlencode(params)
        return f"{self.url}api/rules/show?{encoded_params}"

    def get_audit_log_endpoint(self, from_timestamp: str, to_timestamp: str):
        if self.cloud:
            params = {"startDate": from_timestamp, "endDate": to_timestamp}
        else:
            params = {"from": from_timestamp, "to": to_timestamp}
        encoded_params = parse.urlencode(params)
        if self.cloud:
            return f"{SonarQubeConfig.get_v2_api_url(self.url)}audit-logs/download?{encoded_params}"
        return f"{self.url}api/audit_logs/download?{encoded_params}"
