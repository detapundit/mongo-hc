SUPPORTED_MAJORS = AGG["mongo"]["supported_majors"]
PREFERRED_MAJOR = AGG["mongo"]["preferred_major"]

def mongo_upgrade_advisor(current_version: str) -> dict:
    current_major = ".".join(current_version.split(".")[:2])

    if current_major in SUPPORTED_MAJORS:
        if current_major == PREFERRED_MAJOR:
            return {
                "status": "optimal",
                "current": current_version
            }
        return {
            "status": "supported_but_not_preferred",
            "current": current_version,
            "recommended": PREFERRED_MAJOR
        }

    return {
        "status": "upgrade_required",
        "current": current_version,
        "recommended": PREFERRED_MAJOR
    }
