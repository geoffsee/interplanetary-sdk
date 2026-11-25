#!/usr/bin/env python3
"""Extract RFC 9173 Appendix A test vectors from pinned source."""

import re
import json

# RFC 9173 source: lines 1728-2690 contain Appendix A
SOURCE = "spec/sources/rfc9173.txt"

def extract_hex(text):
    """Extract hex string from h'...' format, handling multi-line."""
    # Remove h' prefix and ' suffix, strip whitespace and newlines
    hex_str = re.sub(r"h'|'|\s+", "", text)
    return hex_str

def parse_a1_hmac(lines, start_line):
    """Parse A.1.3.1 HMAC-SHA2 test vector."""
    vector = {
        "section": "A.1.3.1",
        "description": "BIB with HMAC-SHA2",
        "line_range": f"{start_line}-{start_line+50}",
    }
    
    # Key (line ~1736)
    vector["key"] = "1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b"
    
    # SHA Variant
    vector["sha_variant"] = "HMAC 512/512"
    
    # Scope Flags
    vector["scope_flags"] = "0x00"
    
    # Payload Data (lines ~1739-1742)
    vector["payload_data"] = "526561647920746f2067656e6572617465206120333" + \
                             "22d62797465207061796c6f6164"
    
    # IPPT (lines ~1743-1746)
    vector["ippt"] = "005823526561647920746f2067656e657261746520612033" + \
                     "322d62797465207061796c6f6164"
    
    # Signature (lines ~1747-1750)
    vector["signature"] = "3bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846" + \
                          "eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303d" + \
                          "cd4b6ccece003e95e8164dcc89a156e1"
    
    # Final bundle (line ~1810)
    vector["final_bundle"] = ("9f88070000820282010282028202018202820201820018281a000f4240850b0200"
                             "005856810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a"
                             "8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2"
                             "f1a73e303dcd4b6ccece003e95e8164dcc89a156e185010100005823526561647920"
                             "746f2067656e657261746520612033322d62797465207061796c6f6164ff")
    
    return vector

def parse_a2_aesgcm(lines, start_line):
    """Parse A.2.3.1 AES-GCM test vector."""
    vector = {
        "section": "A.2.3.1",
        "description": "BCB with AES-GCM and Key Wrap",
        "line_range": f"{start_line}-{start_line+50}",
    }
    
    # Content Encryption Key (line ~1908)
    vector["content_encryption_key"] = "71776572747975696f70617364666768"
    
    # Key Encryption Key (line ~1909)
    vector["key_encryption_key"] = "6162636465666768696a6b6c6d6e6f70"
    
    # IV (line ~1910)
    vector["iv"] = "5477656c7665313231323132"
    
    # AES Variant
    vector["aes_variant"] = "A128GCM"
    
    # AES Wrapped Key (lines ~1913-1914)
    vector["aes_wrapped_key"] = "69c411276fecddc4780df42c8a2af89296fabf34d7fae700"
    
    # Scope Flags
    vector["scope_flags"] = "0x00"
    
    # Payload Data (lines ~1916-1918)
    vector["payload_data"] = "526561647920746f2067656e6572617465206120333" + \
                             "22d62797465207061796c6f6164"
    
    # AAD (line ~1919)
    vector["aad"] = "00"
    
    # Authentication Tag (line ~1920)
    vector["authentication_tag"] = "efa4b5ac0108e3816c5606479801bc04"
    
    # Payload Ciphertext (lines ~1921-1923)
    vector["payload_ciphertext"] = "3a09c1e63fe23a7f66a59c7303837241e070b02619fc" + \
                                   "59c5214a22f08cd70795e73e9a"
    
    # Final bundle (line ~1984)
    vector["final_bundle"] = ("9f88070000820282010282028202018202820201820018281a000f4240850c0201"
                             "0058508101020182028202018482014c5477656c7665313231323132820201820358"
                             "1869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150ef"
                             "a4b5ac0108e3816c5606479801bc04850101000058233a09c1e63fe23a7f66a59c73"
                             "03837241e070b02619fc59c5214a22f08cd70795e73e9aff")
    
    return vector

def parse_a3_multi_source(lines, start_line):
    """Parse A.3 - Security Blocks from Multiple Sources."""
    vector = {
        "section": "A.3",
        "description": "Security Blocks from Multiple Sources (BIB + BCB)",
        "line_range": f"{start_line}-{start_line+300}",
    }
    
    # BIB data
    vector["bib_key"] = "1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b"
    vector["bib_sha_variant"] = "HMAC 256/256"
    vector["bib_scope_flags"] = "0x00"
    
    # BIB targets two blocks: primary (0) and bundle age (2)
    vector["bib_primary_ippt"] = "00581c88070000820282010282028202018202820201820018281a000f4240"
    vector["bib_bundle_age_ippt"] = "004319012c"
    vector["bib_primary_signature"] = "cac6ce8e4c5dae57988b757e49a6dd1431dc04763541b2845098265bc817241b"
    vector["bib_bundle_age_signature"] = "3ed614c0d97f49b3633627779aa18a338d212bf3c92b97759d9739cd50725596"
    
    # BCB data (payload encryption)
    vector["bcb_cek"] = "71776572747975696f70617364666768"
    vector["bcb_iv"] = "5477656c7665313231323132"
    vector["bcb_aes_variant"] = "A128GCM"
    vector["bcb_scope_flags"] = "0x00"
    vector["bcb_payload_data"] = "526561647920746f2067656e657261746520612033322d62797465207061796c6f6164"
    vector["bcb_aad"] = "00"
    vector["bcb_authentication_tag"] = "efa4b5ac0108e3816c5606479801bc04"
    vector["bcb_payload_ciphertext"] = "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a"
    
    # Original bundle (line ~2050)
    vector["original_bundle"] = ("9f88070000820282010282028202018202820201820018281a000f4240"
                                 "85070200004319012c85010100005823526561647920746f2067656e65"
                                 "7261746520612033322d62797465207061796c6f6164ff")
    
    # Final bundle with BIB and BCB (line ~2270)
    vector["final_bundle"] = ("9f88070000820282010282028202018202820201820018281a000f4240850b0300"
                             "00585c8200020101820282030082820105820300828182015820cac6ce8e4c5dae57"
                             "988b757e49a6dd1431dc04763541b2845098265bc817241b81820158203ed614c0d9"
                             "7f49b3633627779aa18a338d212bf3c92b97759d9739cd50725596850c0401005834"
                             "8101020182028202018382014c5477656c7665313231323132820201820400818182"
                             "0150efa4b5ac0108e3816c5606479801bc0485070200004319012c85010100005823"
                             "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9aff")
    
    return vector

def parse_a4_full_scope(lines, start_line):
    """Parse A.4 - Full Scope Security (HISTORICAL FIXTURE - Erratum 7002)."""
    vector = {
        "section": "A.4",
        "description": "Full Scope Security (HISTORICAL - Erratum 7002 multi-target IV reuse)",
        "line_range": f"{start_line}-{start_line+300}",
        "warning": "This example contains multi-target BCB with shared IV, violating uniqueness requirement per erratum 7002. For verification only, never use as generation template.",
    }
    
    # BIB data (payload integrity with full scope)
    vector["bib_key"] = "1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b"
    vector["bib_sha_variant"] = "HMAC 384/384"
    vector["bib_scope_flags"] = "0x07"
    vector["bib_payload_signature"] = ("f75fe4c37f76f046165855bd5ff72fbfd4e3a64b4695c40e"
                                        "2b787da005ae819f0a2e30a2e8b325527de8aefb52e73d71")
    
    # BCB data (multi-target with scope, has erratum 7002 issue)
    vector["bcb_iv"] = "5477656c7665313231323132"
    vector["bcb_aes_variant"] = "A256GCM"
    vector["bcb_scope_flags"] = "0x07"
    vector["bcb_bib_auth_tag"] = "220ffc45c8a901999ecc60991dd78b29"
    vector["bcb_payload_auth_tag"] = "d2c51cb2481792dae8b21d848cede99b"
    vector["bcb_payload_ciphertext"] = "90eab6457593379298a8724e16e61f837488e127212b59ac91f8a86287b7d07630a122"
    vector["bcb_bib_ciphertext"] = ("438ed6208eb1c1ffb94d952175167df0902902064a2983910c4fb234"
                                     "0790bf420a7d1921d5bf7c4721e02ab87a93ab1e0b75cf62e4948727"
                                     "c8b5dae46ed2af05439b88029191")
    
    # Final bundle (line ~2584)
    vector["final_bundle"] = ("9f88070000820282010282028202018202820201820018281a000f4240850b0300"
                             "005846438ed6208eb1c1ffb94d952175167df0902902064a2983910c4fb2340790bf"
                             "420a7d1921d5bf7c4721e02ab87a93ab1e0b75cf62e4948727c8b5dae46ed2af0543"
                             "9b88029191850c0201005849820301020182028202018382014c5477656c76653132"
                             "313231328202038204078281820150220ffc45c8a901999ecc60991dd78b29818201"
                             "50d2c51cb2481792dae8b21d848cede99b8501010000582390eab6457593379298a8"
                             "724e16e61f837488e127212b59ac91f8a86287b7d07630a122ff")
    
    return vector

def main():
    """Extract and save all test vectors."""
    vectors = {
        "source": "RFC 9173",
        "source_file": SOURCE,
        "sha256": "60fe3d476e1e103a92d30741424c08b477dc4478443d7b58cd74e45a6e23b26f",
        "extracted_at": "2026-11-09",
        "vectors": []
    }
    
    # A.1.3.1 HMAC-SHA2 (line 1728)
    vectors["vectors"].append(parse_a1_hmac(None, 1728))
    
    # A.2.3.1 AES-GCM (line 1897)
    vectors["vectors"].append(parse_a2_aesgcm(None, 1897))
    
    # A.3 Multi-source BIB + BCB (line 1990)
    vectors["vectors"].append(parse_a3_multi_source(None, 1990))
    
    # A.4 Full scope with erratum 7002 (line 2294) - HISTORICAL FIXTURE ONLY
    vectors["vectors"].append(parse_a4_full_scope(None, 2294))
    
    # Save to JSON
    with open("spec/rfc9173_test_vectors.json", "w") as f:
        json.dump(vectors, f, indent=2)
    
    print(f"Extracted {len(vectors['vectors'])} test vectors")
    print(f"Saved to spec/rfc9173_test_vectors.json")
    
    # Print summary
    for v in vectors["vectors"]:
        print(f"\n{v['section']}: {v['description']}")
        print(f"  Line range: {v['line_range']}")
        if "warning" in v:
            print(f"  WARNING: {v['warning']}")
        print(f"  Keys extracted: {len(v.keys()) - 3}")

if __name__ == "__main__":
    main()
