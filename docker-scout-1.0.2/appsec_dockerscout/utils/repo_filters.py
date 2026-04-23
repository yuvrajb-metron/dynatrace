"""
Repository filter: keep images whose org or org/repo matches an allow list.

Supports partial match and org or org/repo format (e.g. "myorg" or "myorg/myrepo").
"""

from typing import List

from appsec_dockerscout.models import ImageRef
from dynatrace_extension.sdk.extension import extension_logger as logger


def apply_repo_filter(
    images: List[ImageRef], repo_list: List[str]
) -> List[ImageRef]:
    """
    Keep only images whose org or org/repo matches any entry in repo_list.

    Args:
        images: List of image refs from discovery.
        repo_list: Allowed org names or "org/repo" patterns (partial match;
            e.g. "myorg" matches that org; "myorg/repo" matches that repo or
            repos containing that path).

    Returns:
        Filtered list of ImageRef. If repo_list is empty, returns images unchanged.
    """
    logger.debug(
        f"apply_repo_filter started: images_count={len(images)}, repo_list={repo_list}"
    )
    if not repo_list:
        return images
    normalized_allowlist_patterns = [
        raw_pattern.strip().lower()
        for raw_pattern in repo_list
        if raw_pattern and isinstance(raw_pattern, str)
    ]
    filtered_images: List[ImageRef] = []
    for image_ref in images:
        namespace_lower = image_ref.org.lower()
        namespace_and_repo_lower = f"{image_ref.org}/{image_ref.repo}".lower()
        for allowlist_pattern in normalized_allowlist_patterns:
            if "/" in allowlist_pattern:
                repo_path_matches = (
                    namespace_and_repo_lower == allowlist_pattern
                    or namespace_and_repo_lower.endswith("/" + allowlist_pattern)
                    or allowlist_pattern in namespace_and_repo_lower
                )
                if repo_path_matches:
                    filtered_images.append(image_ref)
                    break
            else:
                org_matches = (
                    namespace_lower == allowlist_pattern
                    or allowlist_pattern in namespace_lower
                )
                if org_matches:
                    filtered_images.append(image_ref)
                    break
    logger.debug(
        f"apply_repo_filter finished: input={len(images)}, "
        f"output={len(filtered_images)}"
    )
    return filtered_images
