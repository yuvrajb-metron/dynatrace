from utils import urlparse, convert_to_ip, qualys_timestamp_from_datetime


base_url = "https://qualysapi.qg2.apps.qualys.com"

parse_result = urlparse(base_url)

print(parse_result.netloc.split(".")[0])