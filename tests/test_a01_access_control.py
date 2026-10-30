import requests

JUICE_URL = "http://localhost:3000"

def test_unauthenticated_ftp_listing():
    """A01: Can an anonymous user list the /ftp/ directory?"""
    r = requests.get(f"{JUICE_URL}/ftp/", timeout=5)
    # If we get a directory listing, that's broken access control
    assert "acquisitions.md" in r.text or "legal.md" in r.text, \
        "A01: FTP directory should not be publicly listable"
    # If we reach here, the test "passed" meaning the vuln EXISTS
    print("🔴 A01 Finding: Unauthenticated FTP directory listing exposed")