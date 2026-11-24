# Public Suffix List

ICANN registration rules from https://publicsuffix.org/list/public_suffix_list.dat, licensed under the [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/). The JSON records the source version and SHA-256. Rules are normalized to ASCII IDNA. Private-service suffixes are deliberately excluded because RDAP describes the registered parent domain.

Refresh with `python3 scripts/update_suffixes.py`, review the generated JSON, test and commit. The build remains offline.
