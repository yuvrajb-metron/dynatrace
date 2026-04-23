from typing import Optional, Dict, Any

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


class QualysObject:

    def original_content_xml(self) -> str:
        try:
            return ET.tostring(self.original_element, encoding="utf8").decode("utf-8")
        except Exception as e:
            return ""
