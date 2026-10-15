def parse_ip_report(result):

    if "data" not in result:
        return {
            "error": result
        }

    attributes = result["data"]["attributes"]

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    analysis_results = attributes.get(
        "last_analysis_results",
        {}
    )

    detections = []

    for engine, details in analysis_results.items():

        category = details.get("category")

        if category in ["malicious", "suspicious"]:

            detections.append({
                "engine": engine,
                "category": category,
                "result": details.get("result")
            })

    parsed_data = {

        "country": attributes.get("country"),

        "continent": attributes.get("continent"),

        "asn": attributes.get("asn"),

        "as_owner": attributes.get("as_owner"),

        "network": attributes.get("network"),

        "reputation": attributes.get("reputation"),

        "tags": attributes.get("tags", []),

        "malicious": stats.get("malicious", 0),

        "suspicious": stats.get("suspicious", 0),

        "harmless": stats.get("harmless", 0),

        "undetected": stats.get("undetected", 0),

        "timeout": stats.get("timeout", 0),

        "detections": detections
    }

    return parsed_data
