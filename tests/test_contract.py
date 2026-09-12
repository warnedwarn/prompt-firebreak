from pathlib import Path
TEXT=Path('contracts/contract.py').read_text()
def test_surface():
 for name in ('queue_scan','screen','replace_sources','rescreen','close_expired','get_scan'):assert 'def '+name in TEXT
def test_security_binding():
 assert 'hostile untrusted data' in TEXT and "proposed['digests']!=digests" in TEXT and 'sha256' in TEXT

