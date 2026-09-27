# GeoIP databases

The one part of the install that cannot be automated, and why.

## Why this is manual

MaxMind's GeoLite2 databases are free but not anonymous: since December 2019
they require an account and a signed end-user licence, and downloads are
authenticated with a per-account licence key. A key baked into this repository
would be one person's credential shared with everyone who clones it — against
MaxMind's terms, and a secret in version control besides.

So `offline/build_wheelhouse.sh` does not fetch them, and `offline/install.sh`
checks for them and tells you they are missing rather than failing.

## What is lost without them

Nothing stops working. The pipeline logs the absence once, per database, and
continues:

```
GeoIP database missing: data/geoip/GeoLite2-Country.mmdb — enrichment columns will be null
```

| Still works | Degraded |
| --- | --- |
| Ingest, validation, quarantine | `country` is null on every row |
| Clustering, entity collapse, features | `asn` is null, so hosting/VPN detection falls back to the starter ASN list in `config.yaml` (`geoip.high_risk_asns`) and the snapshot in `data/intel/hosting_asns.txt` |
| Rules, anomaly, GNN, taint, fusion | The case report has no geographic context |
| Origin estimation and the IP-class badges | ASN-based correlation weighting is weaker, so attribution leads are less well separated |
| The console, the live monitor, the red team, the PDF export | |

Read that as: the system demonstrates fully without GeoIP, and is *better* with
it. If you have five minutes and a machine with internet, spend them.

## Getting them

1. Create a free account at <https://www.maxmind.com/en/geolite2/signup>.
   A name and an email address; no payment details.
2. Sign in, then **Manage License Keys → Generate new license key**.
3. **Download Databases** and take these two, in **MaxMind DB binary (.mmdb)**
   format — not CSV:
   * *GeoLite2 Country*
   * *GeoLite2 ASN*
4. Each arrives as `GeoLite2-Country_YYYYMMDD.tar.gz`. Unpack and take the
   `.mmdb` file out of the directory inside:

   ```sh
   tar xzf GeoLite2-Country_*.tar.gz
   tar xzf GeoLite2-ASN_*.tar.gz
   mkdir -p data/geoip
   cp GeoLite2-Country_*/GeoLite2-Country.mmdb data/geoip/
   cp GeoLite2-ASN_*/GeoLite2-ASN.mmdb         data/geoip/
   ```

5. Copy `data/geoip/` to the air-gapped machine, in the repository, at the same
   path.

The filenames matter — `config.yaml` names them:

```yaml
geoip:
  country_db: data/geoip/GeoLite2-Country.mmdb
  asn_db: data/geoip/GeoLite2-ASN.mmdb
```

Point those elsewhere if your copies live somewhere else; nothing else in the
system hardcodes the paths.

## Checking they work

```sh
.venv/bin/python -c "
import config, pandas as pd
from ingest.geoip import GeoIp, enrich
frame = pd.DataFrame({'src_ip': ['8.8.8.8'], 'dst_ip': ['1.1.1.1']})
enrich(frame, GeoIp(config.load()), cfg=config.load())
print(frame[[c for c in frame.columns if c not in ('src_ip', 'dst_ip')]].to_dict('records'))
"
```

With the databases in place this prints a country and an ASN. Without them it
prints nulls and logs the warning above — which is the same thing the pipeline
will do, so this is a faithful check.

## The demo without them

The demo dataset is generated, and the generator writes its own `asn` and
`geo_country` on every relay row. `ingest.geoip.enrich` falls back to those
fields when no database answers, so demo peer profiles are never blank. Their
Network block is labelled with its source (`profile._network`):

| basis shown | meaning |
| --- | --- |
| GeoLite2 lookup (ingest.geoip) | a local `.mmdb` answered |
| synthetic: the demo generator's own ASN and country, not a GeoIP lookup | simulated data, no database |
| the capture's own ASN and country fields; no GeoIP database installed | real data carrying its own fields |
| no ASN or country: GeoLite2 not installed | nothing answered |

The synthetic values are the generator's inventions. The ASN organisation name
stays empty without GeoLite2, since the generator does not make one up.

## Licence

Checked against MaxMind's GeoLite2 End User License Agreement
(<https://www.maxmind.com/en/geolite2/eula>) on 2026-09-27. The data is under
Creative Commons Attribution-ShareAlike 4.0, and the EULA adds terms on top.
In summary (read the EULA itself before relying on this):

* **Attribution.** Products using the data carry MaxMind's attribution, in
  the form the EULA gives:

  > This product includes GeoLite Data created by MaxMind, available from
  > <https://www.maxmind.com>.

* **Keep it current.** When MaxMind releases an update you are to use it, and
  destroy old versions within thirty days of the release. An air-gapped copy
  therefore needs refreshing about monthly, by the same five-minute route.
* **No redistribution without consent.** Beyond what the CC licence permits,
  disclosing the databases to third parties needs MaxMind's prior written
  consent. That is one more reason, besides the licence key, that they are
  never bundled or committed.
* **No locating individuals.** The EULA forbids using the data to identify or
  locate a specific household, individual or street address. This system
  uses country and ASN only, as context and to discount shared
  infrastructure. Keep it that way.

The databases are **not** committed to this repository: `data/geoip/*` is in
`.gitignore`, and `*.mmdb` again after it.
