import requests

from sonarqube.clients.base_schema import BaseSchema
from sonarqube.config.sonarqube_config import SonarQubeConfig
from sonarqube.utils.pagination_util import pages_for


class TextRange(BaseSchema):
    start_line: int
    end_line: int
    start_offset: int
    end_offset: int


class Impact(BaseSchema):
    software_quality: str
    severity: str


class Context(BaseSchema):
    display_name: str
    key: str


class DescriptionSection(BaseSchema):
    key: str
    content: str
    context: Context | None = None


class Param(BaseSchema):
    key: str
    desc: str
    default_value: str


class Rule(BaseSchema):
    key: str
    repo: str | None = None
    name: str | None = None
    html_desc: str | None = None
    severity: str | None = None
    status: str | None = None
    internal_key: str | None = None
    template: bool | None = None
    tags: list | None = None
    sys_tags: list[str] | None = None
    rem_fn_type: str | None = None
    rem_fn_gap_multiplier: str | None = None
    rem_fn_base_effort: str | None = None
    default_rem_fn_type: str | None = None
    default_rem_fn_gap_multiplier: str | None = None
    default_rem_fn_base_effort: str | None = None
    rem_fn_overloaded: bool | None = None
    gap_description: str | None = None
    lang: str | None = None
    lang_name: str | None = None
    scope: str | None = None
    is_external: bool | None = None
    type: str | None = None
    clean_code_attribute_category: str | None = None
    clean_code_attribute: str | None = None
    impacts: list[Impact] | None = None
    description_sections: list[DescriptionSection] | None = None
    params: list[Param] | None = None


class Issue(BaseSchema):
    key: str
    rule: str | None = None
    rule_key: str | None = None
    severity: str | None = None
    component: str | None = None
    project: str | None = None
    line: int | None = None
    hash: str | None = None
    text_range: TextRange | None = None
    flows: list | None = None
    status: str | None = None
    message: str | None = None
    effort: str | None = None
    debt: str | None = None
    author: str | None = None
    tags: list[str] | None = None
    creation_date: str | None = None
    update_date: str | None = None
    type: str | None = None
    scope: str | None = None
    quick_fix_available: bool | None = None
    message_formattings: list | None = None
    code_variants: list | None = None
    clean_code_attribute: str | None = None
    clean_code_attribute_category: str | None = None
    impacts: list[Impact] | None = None
    issue_status: str | None = None
    prioritized_rule: bool | None = None
    vulnerability_probability: str | None = None
    security_category: str | None = None
    assignee: str | None = None


class IssuesClient:
    def __init__(self, config: SonarQubeConfig, severities: list[str], logger):
        self.config = config
        self.logger = logger
        self.severities = severities

    def get_issues(self, component: str, created_at: str) -> list[Issue]:
        issues = pages_for(
            self.config.get_issues_endpoint(component, self.severities, created_at),
            self.config.get_headers(),
            self.config.verify,
            "issues",
            self.logger,
            proxies=self.config.get_proxies(),
        )
        self.logger.debug(
            f"Successfully got {len(issues)} issues for component {component} for analysis at {created_at}"
        )
        return [Issue(**issue) for issue in issues]

    def get_rule_details(self, rule: str) -> Rule:
        response = requests.get(
            self.config.get_rule_endpoint(rule),
            headers=self.config.get_headers(),
            verify=self.config.verify,
            proxies=self.config.get_proxies(),
        )
        response.raise_for_status()
        self.logger.debug(f"successfully got rule details for rule {rule}")
        return Rule(**response.json()["rule"])
