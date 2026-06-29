"""Decode the SaaS / vendor footprint a domain leaks through DNS. The TXT
verification tokens, the SPF includes, and the MX hosts each name the products an
organisation uses. This is pure interpretation of records the scan already
collected, turning raw DNS noise into a readable technology profile.
"""
from __future__ import annotations

# Substring found in a TXT verification token -> (product, category).
TXT_SIGNS: dict[str, tuple[str, str]] = {
    "google-site-verification": ("Google Search Console", "Google"),
    "facebook-domain-verification": ("Meta / Facebook", "Marketing"),
    "apple-domain-verification": ("Apple Business Manager", "Productivity"),
    "atlassian-domain-verification": ("Atlassian", "Engineering"),
    "atlassian-sending-domain": ("Atlassian", "Engineering"),
    "calendly-site-verification": ("Calendly", "Productivity"),
    "calendly": ("Calendly", "Productivity"),
    "loom-site-verification": ("Loom", "Productivity"),
    "jamf": ("Jamf", "IT / MDM"),
    "krisp-domain-verification": ("Krisp", "Productivity"),
    "stripe-verification": ("Stripe", "Payments"),
    "shopify": ("Shopify", "E-commerce"),
    "docusign": ("DocuSign", "Productivity"),
    "dropbox-domain-verification": ("Dropbox", "Storage"),
    "zoom-domain-verification": ("Zoom", "Communication"),
    "webexdomainverification": ("Cisco Webex", "Communication"),
    "slack-domain-verification": ("Slack", "Communication"),
    "notion-domain-verification": ("Notion", "Productivity"),
    "zendeskverification": ("Zendesk", "Support"),
    "hubspot-developer-verification": ("HubSpot", "Marketing"),
    "miro-verification": ("Miro", "Design"),
    "figma-domain-verification": ("Figma", "Design"),
    "adobe-idp-site-verification": ("Adobe", "Design"),
    "adobe-sign-verification": ("Adobe Sign", "Productivity"),
    "okta-verification": ("Okta", "Identity"),
    "onelogin-verification": ("OneLogin", "Identity"),
    "duo_sso_verification": ("Duo Security", "Identity"),
    "mongodb-site-verification": ("MongoDB Atlas", "Cloud"),
    "yandex-verification": ("Yandex", "Email"),
    "pardot": ("Salesforce Pardot", "Marketing"),
    "salesforce": ("Salesforce", "CRM"),
    "citrix-verification": ("Citrix", "IT"),
    "workplace-domain-verification": ("Meta Workplace", "Communication"),
    "canva-site-verification": ("Canva", "Design"),
    "asana-domain-verification": ("Asana", "Productivity"),
    "intercom-verification": ("Intercom", "Support"),
    "knowbe4-site-verification": ("KnowBe4", "Security"),
    "smartsheet": ("Smartsheet", "Productivity"),
    "twilio-domain-verification": ("Twilio", "Communication"),
    "ms=": ("Microsoft 365", "Microsoft"),
}

# Substring found in an SPF include -> (sender, category).
SPF_SIGNS: dict[str, tuple[str, str]] = {
    "_spf.google.com": ("Google Workspace", "Email"),
    "spf.protection.outlook.com": ("Microsoft 365", "Email"),
    "sendgrid.net": ("SendGrid", "Email"),
    "mailgun.org": ("Mailgun", "Email"),
    "servers.mcsv.net": ("Mailchimp", "Marketing"),
    "_spf.salesforce.com": ("Salesforce", "CRM"),
    "spf.mandrillapp.com": ("Mandrill", "Email"),
    "amazonses.com": ("Amazon SES", "Email"),
    "_spf.intercom.io": ("Intercom", "Support"),
    "spf.mailjet.com": ("Mailjet", "Email"),
    "_spf.qualtrics.com": ("Qualtrics", "Marketing"),
    "sparkpostmail.com": ("SparkPost", "Email"),
    "zendesk.com": ("Zendesk", "Support"),
    "hubspotemail.net": ("HubSpot", "Marketing"),
    "spf.hubspot.com": ("HubSpot", "Marketing"),
    "pphosted.com": ("Proofpoint", "Security"),
    "mimecast.com": ("Mimecast", "Security"),
    "stspg-customer.com": ("Statuspage", "Engineering"),
    "spf.constantcontact.com": ("Constant Contact", "Marketing"),
}

# Substring found in an MX host -> provider.
MX_SIGNS: dict[str, str] = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast": "Mimecast",
    "messagingengine.com": "Fastmail",
    "zoho": "Zoho Mail",
    "yandex": "Yandex Mail",
    "secureserver.net": "GoDaddy Email",
    "mailgun": "Mailgun",
}


def detect_saas(txt_records=None, spf_includes=None, mx_records=None) -> dict:
    """Build the SaaS / vendor profile from TXT tokens, SPF includes, and MX hosts."""
    found: dict[str, dict] = {}

    def add(name: str, category: str, evidence: str) -> None:
        if name not in found:
            found[name] = {"name": name, "category": category, "evidence": evidence}

    for txt in txt_records or []:
        low = str(txt).lower()
        for sign, (name, cat) in TXT_SIGNS.items():
            if sign in low:
                add(name, cat, "TXT")
    for include in spf_includes or []:
        low = str(include).lower()
        for sign, (name, cat) in SPF_SIGNS.items():
            if sign in low:
                add(name, cat, "SPF")
    for mx in mx_records or []:
        low = str(mx).lower()
        for sign, name in MX_SIGNS.items():
            if sign in low:
                add(name, "Email", "MX")

    services = sorted(found.values(), key=lambda s: (s["category"], s["name"]))
    return {"status": "ok", "count": len(services), "services": services}
