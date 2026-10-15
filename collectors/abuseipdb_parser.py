def parse_ip_report(result):

    if "data" not in result:

        return {
            "error": result
        }

    data = result["data"]

    parsed_data = {

        "ip": data.get("ipAddress"),

        "public": data.get("isPublic"),

        "ip_version": data.get("ipVersion"),

        "whitelisted": data.get("isWhitelisted"),

        "abuse_confidence_score": data.get(
            "abuseConfidenceScore"
        ),

        "country": data.get("countryCode"),

        "usage_type": data.get("usageType"),

        "isp": data.get("isp"),

        "domain": data.get("domain"),

        "total_reports": data.get("totalReports"),

        "distinct_users": data.get(
            "numDistinctUsers"
        ),

        "last_reported": data.get(
            "lastReportedAt"
        )
    }

    return parsed_data
