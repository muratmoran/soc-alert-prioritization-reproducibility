# Data sources, licences and checksums

## AIT Alert Data Set, version 1

- Creators: Max Landauer, Florian Skopik, Markus Wurzenberger (AIT Austrian Institute of Technology). Zenodo, 2023. doi:10.5281/zenodo.8263181. Licence: CC BY 4.0.
- Paper: Landauer, Skopik, Wurzenberger (2024), Introducing a New Alert Data Set for Multi-Step Attack Analysis, doi:10.1145/3675741.3675748.
- Published MD5 checksums (Zenodo record API), verified against the copies used (WP0 provenance manifest):

| File | Published MD5 | Observed MD5 | Included |
| --- | --- | --- | --- |
| ait_ads.zip | `43db6b1f0996e0024befd617706c50e9` | `43db6b1f0996e0024befd617706c50e9` | no (download) |
| labels.csv | `60ff33796c77fd2136c4d1a4bc841bd9` | `60ff33796c77fd2136c4d1a4bc841bd9` | yes |

SHA-256 of the extracted alert files used:

| File | Bytes | SHA-256 |
| --- | --- | --- |
| fox_aminer.json | 8,879,125 | `3de2f6d87c843b99dbc5ca3d5225fcd42f60938187d6391dc33d01c216fffcb4` |
| fox_wazuh.json | 491,410,473 | `e03787f1a4402b034c4c2648c0632d92c5982aecaa6146837695ca7aa3023b51` |
| harrison_aminer.json | 8,693,273 | `bf10cf4aae7513f02da68b6bf5221c8bdc2a7ecffde25d534455da7f1823dd92` |
| harrison_wazuh.json | 632,912,134 | `6c5571aca9b55812f7497a929008a740515c9f866f026f25ddf94cc01ac1ad10` |
| russellmitchell_aminer.json | 3,411,024 | `f8f7698833836d0e24624d53981474795ec6f8991a1b33d5fb2e9e411c24752f` |
| russellmitchell_wazuh.json | 45,282,051 | `da4b882de7df765d4fbedd772a5bf892e7a440580d3654c585d6d124bfb94832` |
| santos_aminer.json | 3,634,879 | `45d9e531e66b047df69dfe128548e1d8f314b8c6c2df976a026cc47709b7df9f` |
| santos_wazuh.json | 145,438,925 | `df298d52ab555a75b1e6a60e80aae973e845d85ba9875d001bd2f5f4f3b5097b` |
| shaw_aminer.json | 1,944,470 | `1e18cd6b3f94ec32c72741351887f975c3157c7c271adcd5e4589617c70c161c` |
| shaw_wazuh.json | 74,755,213 | `45e34b65ce08c6a49b0ba52a4f36dbe5829d26240a2acccf8b3842201b6afca8` |
| wardbeck_aminer.json | 2,583,498 | `cc4f073ff9f7bea57b17aa263d58c7cc0b4a7a3b9499cdf3491cf1510d3a98bd` |
| wardbeck_wazuh.json | 96,564,119 | `b4e483c67e4de2a20b1b559692981e912fb83f1d1831b6e1f7e5760b16fe7117` |
| wheeler_aminer.json | 10,220,678 | `aa2f2240d627f6cd37916f1ab7ad6452edf51a01f8ab831b29f9d0e2567b357e` |
| wheeler_wazuh.json | 650,679,741 | `3dbbb2da0d190eb5d0b9384a724806c1c65d170e8e84955650b778f3019e40fc` |
| wilson_aminer.json | 7,570,675 | `08f87d83a5b4095b7fc7b2fb07ed105bc3cfd5bf23ca25529f2f1b932d51613f` |
| wilson_wazuh.json | 673,722,526 | `dddc4b891425750c25bfe7fceb95f68e0dd5bd4e93f7a1d16577024703c41478` |

Derived caches included (identity records alongside each file):

| Cache | Rows | SHA-256 |
| --- | --- | --- |
| ait_canonical_original_labels.pkl.gz | 2655821 | `c5702421b4e563c909d7d4002f1cca96c5ba08265a47b6a6249726c6dde133be` |
| ait_native_score_provenance.pkl.gz | 2655821 | `d2f4e1cf04987eff35526d4dcd6f1b0350748054de5a6e83fac2fca26c5e7522` |

## UWF-ZeekData24

- University of West Florida, https://datasets.uwf.edu/ (CC BY 4.0 statement on the portal). Paper: Elam, Mink, Bagui, Plenkers, Bagui (2025), Data 10(5):59, doi:10.3390/data10050059.
- No published checksums were available; the SHA-256 values below were recorded when the files were first materialised (`docs/revision/wp7/uwf/uwf_summary.json`).

| File | Rows | SHA-256 |
| --- | --- | --- |
| Benign.csv | 47,906 | `272677c8c7bbe7ab57b040f63ed8bbf92d0b5716adb05444258274eed000ab3f` |
| Credential_Access.csv | 43,494 | `6448eeebbb5dfaf88bb45f81a2fa8fd3b2a3e635090da2e50b0177bd71430424` |
| Defense_Evasion.csv | 326 | `801594d09ce3b9a18f86199a4dbff04511e375910f3d0d932a6dcde1153cb101` |
| Exfiltration.csv | 23 | `b485153727b8a630582838eebf75c924cb0b49476b69de1b728b85d4371827f0` |
| Initial_Access.csv | 561 | `faf6b9e07a7dab23ce364898772af062f51ddef4feb9329778750f8ed699d0e6` |
| Persistence.csv | 326 | `52b19554a53a7da044fbf25f8546702e00043cca43673ebe41ee091cfb2009c8` |
| Privilege_Escalation.csv | 326 | `5933fa87bf55f54821705754be357ea1fa0e347b440c3af0590be6e03bd04877` |
| Reconnaissance.csv | 2,909 | `13bf1c7fe9364a91a18d858683fee999baf6567ca65e2077829df089107ff7b0` |

## NF-UQ-NIDS-v2

- Not redistributed and not used by the revised analysis (WP6 deferred). WP0 status: not verified: 13.7 GB iCloud placeholder exceeds free disk.
