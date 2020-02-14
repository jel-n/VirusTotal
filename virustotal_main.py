#
# Python utility for querying virustotal for relevant information to be used during a security investigation
#
# Usage: python virustotal_main.py -i <ip address
# Example: python virustotal_main.py -i 8.8.8.8
#
import requests
import pandas as pd
import argparse
from datetime import datetime, timezone

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="IP address lookup.")
args = parser.parse_args()

apikey = "API KEY"

def main():

    if args.ip:
        r = requests.get(f"https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={apikey}&ip={args.ip}").json()

        try:
            print(f"\nCertificate Date: {format(datetime.fromtimestamp((r['https_certificate_date'    ]), timezone.utc))}")

        except KeyError:
            print("\nCertificate Date: N/A")

            print(f"ASN: {r['asn']}")
            print(f"Owner: {r['as_owner']}")

            # -- DataFrame for domains which resolved to this ip address -- #
            df = pd.DataFrame(r["resolutions"])
            sorted = df.sort_values(by=["last_resolved"], ascending=True).head()
            print(f"\n {sorted.reset_index(drop=True)}")

            # -- DataFrame for URLs hosted in this ip address -- #
            df2 = pd.DataFrame(r["detected_urls"])
            sorted_urls = df2.sort_values(by=["positives"], ascending=False).head()
            print(f"\n {sorted_urls.reset_index(drop=True)}")

            # -- DataFrame for samples that were downloaded with this IP address -- #
            download_samples = pd.DataFrame(r["detected_downloaded_samples"])
            sorted_downloads = download_samples.sort_values(by=["positives"], ascending=False).head()
            print(f"\n {sorted_downloads.reset_index(drop=True)}")

    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
