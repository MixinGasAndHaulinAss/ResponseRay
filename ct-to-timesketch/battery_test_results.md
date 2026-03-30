# CloudRules Battery Test Results

**Binary**: ct-to-timesketch 20260310.2 (Go, streaming, full-extraction, CloudRules)
**Date**: 2026-03-10 00:00
**CloudRules**: CloudRules_rv3160001.json.gz
**Starting disk**: 256Gi free

## Summary Table

| # | Organization | Hostname | GZ Size | Events | CR Detections | CR Events | Top Score | Time | JSONL |
|---|-------------|----------|---------|--------|---------------|-----------|-----------|------|-------|
| 1 | Bertie County Schools | BCS-PDC1.bertie.k12.nc.us | 884M | 3930149 | 10 | 10 | NOTABLE | 5m2s | OK |
| 2 | Bertie County Schools | BCS-PDC2.bertie.k12.nc.us | 905M | 3078530 | 2 | 2 | NOTABLE | 3m34s | OK |
| 3 | Bertie County Schools | TIMS24.bertie.k12.nc.us | 799M | 4039193 | 4 | 4 | NOTABLE | 5m13s | OK |
| 4 | Bladen County | dc2.bladenco.local | 572M | 2892928 | 2502 | 2502 | NOTABLE | 2m57s | OK |
| 5 | Cherokee County Schools | DC0.cherokee.k12.nc.us | 977M | 3413161 | 21 | 21 | UNKNOWN | 3m31s | OK |
| 6 | City of Kannapolis | KAN-GW2 | 800M | 950107 | 22 | 22 | NOTABLE | 1m19s | OK |
| 7 | Guilford County | ADDEVSVS23.Guilford.com | 1.7G | 7357169 | 18 | 14 | NOTABLE | 22m44s | OK |
| 8 | Guilford County | DCDT01.Guilford.com | 1.0G | 3276116 | 0 | 0 | none | 3m35s | OK |
| 9 | Guilford County | DCDT05.Guilford.com | 995M | 2563159 | 0 | 0 | none | 2m48s | OK |
| 10 | Guilford County | ETFEDOS14.Guilford.com | 1.3G | 4730472 | 0 | 0 | none | 5m12s | OK |
| 11 | Guilford County | ETRDSTSTWV14.Guilford.com | 727M | 2365520 | 0 | 0 | none | 2m7s | OK |
| 12 | Guilford County | ETRDSWSWV11.Guilford.com | 572M | 2553996 | 0 | 0 | none | 2m9s | OK |
| 13 | Guilford County | ETRDSWSWV11.Guilford.com | 826M | 3280996 | 0 | 0 | none | 2m52s | OK |
| 14 | Guilford County | gcadvauth.Guilford.com | 906M | 3644329 | 306 | 300 | NOTABLE | 3m51s | OK |
| 15 | Guilford County | LEDELL09235.Guilford.com | 2.0G | 2340707 | 33 | 33 | NOTABLE | 3m7s | OK |
| 16 | Guilford County | RDP-GATEWAY.personcounty.local | 1.0G | 2453703 | 95 | 95 | NOTABLE | 2m15s | OK |
| 17 | Lenoir County | LC911AD.lc911.local | 664M | 1833789 | 5 | 1 | NOTABLE | 2m1s | OK |
| 18 | Lenoir County | lcad03.lenoir.local | 823M | 2660198 | 9 | 4 | NOTABLE | 2m20s | OK |
| 19 | Lenoir County | LCRODCOTTDC.cott.local | 650M | 2829012 | 46 | 46 | NOTABLE | 2m22s | OK |
| 20 | New Hanover County | SHER1Q85LS3.nhcgov.com | 2.5G | 3792572 | 5 | 1 | NOTABLE | 5m2s | OK |
| 21 | Robeson County Sheriff | RCSO-HV01.robeson.domain | 976M | 2379320 | 7622 | 7613 | NOTABLE | 2m42s | OK |
| 22 | Robeson County Sheriff | RCSO-HV02.robeson.domain | 854M | 1896600 | 4838 | 4838 | NOTABLE | 2m12s | OK |
| 23 | Robeson County Sheriff | RCSORMS.robeson.domain | 1.1G | 2235370 | 4224 | 4224 | NOTABLE | 2m40s | OK |
| 24 | Sleuth Kit Labs | FILESERVER-01.reynholm.local | 516M | 441889 | 70 | 14 | NOTABLE | 39s | OK |
| 25 | Sleuth Kit Labs | RAGINGBULL.reynholm.local | 1.3G | 1347890 | 152 | 84 | NOTABLE | 1m58s | OK |
| 26 | Sleuth Kit Labs | REYNHOLM-DC01.reynholm.local | 551M | 888793 | 47 | 15 | NOTABLE | 1m10s | OK |
| 27 | Town of Cornelius | DC00 | 727M | 4528720 | 25 | 25 | NOTABLE | 5m25s | OK |
| 28 | Town of Cornelius | DC02 | 709M | 4759934 | 26 | 26 | NOTABLE | 5m45s | OK |

## Per-Capture Assessments

### 1. Bertie County Schools / BCS-PDC1.bertie.k12.nc.us

> **Bertie County Schools / BCS-PDC1.bertie.k12.nc.us** -- Processed 884M capture producing 3930149 timeline events in 5m2s. CloudRules identified 10 detections across 10 events (10 NOTABLE). Top findings: Top(types:) DATA_TRANSFER_TOOL(8) REMOTE_ACCESS_SOFTWARE(2) . Remote management software detected -- verify whether authorized for this endpoint. Data transfer tools present -- assess for potential exfiltration activity. JSONL validation: OK.

### 2. Bertie County Schools / BCS-PDC2.bertie.k12.nc.us

> **Bertie County Schools / BCS-PDC2.bertie.k12.nc.us** -- Processed 905M capture producing 3078530 timeline events in 3m34s. CloudRules identified 2 detections across 2 events (2 NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(2) Tagged(detections) . Remote management software detected -- verify whether authorized for this endpoint. JSONL validation: OK.

### 3. Bertie County Schools / TIMS24.bertie.k12.nc.us

> **Bertie County Schools / TIMS24.bertie.k12.nc.us** -- Processed 799M capture producing 4039193 timeline events in 5m13s. CloudRules identified 4 detections across 4 events (4 NOTABLE). Top findings: Top(types:) EXTERNAL_STORAGE_DOMAIN(4) Tagged(detections) . Suspicious domain activity observed -- review for C2 or exfiltration staging. JSONL validation: OK.

### 4. Bladen County / dc2.bladenco.local

> **Bladen County / dc2.bladenco.local** -- Processed 572M capture producing 2892928 timeline events in 2m57s. CloudRules identified 2502 detections across 2502 events (2502 NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(2502) Tagged(detections) . Remote management software detected -- verify whether authorized for this endpoint. JSONL validation: OK.

### 5. Cherokee County Schools / DC0.cherokee.k12.nc.us

> **Cherokee County Schools / DC0.cherokee.k12.nc.us** -- Processed 977M capture producing 3413161 timeline events in 3m31s. CloudRules identified 21 detections across 21 events. Top findings: Top(types:) DLL_INJECTION(21) Tagged(detections) . DLL injection indicators found -- investigate memory-resident threats. JSONL validation: OK.

### 6. City of Kannapolis / KAN-GW2

> **City of Kannapolis / KAN-GW2** -- Processed 800M capture producing 950107 timeline events in 1m19s. CloudRules identified 22 detections across 22 events (21 NOTABLE, 1 LIKELY_NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(21) BADLIST_HIT(1) . Remote management software detected -- verify whether authorized for this endpoint. JSONL validation: OK.

### 7. Guilford County / ADDEVSVS23.Guilford.com

> **Guilford County / ADDEVSVS23.Guilford.com** -- Processed 1.7G capture producing 7357169 timeline events in 22m44s. CloudRules identified 18 detections across 14 events (17 NOTABLE, 1 LIKELY_NOTABLE). Top findings: Top(types:) DATA_TRANSFER_TOOL(13) WINDOWS_DEFENDER_EXCLUSION_RULE(2) . Data transfer tools present -- assess for potential exfiltration activity. Windows Defender configuration changes detected -- check for intentional security weakening. JSONL validation: OK.

### 8. Guilford County / DCDT01.Guilford.com

> **Guilford County / DCDT01.Guilford.com** -- Processed 1.0G capture producing 3276116 timeline events in 3m35s. CloudRules found no detections. JSONL validation: OK.

### 9. Guilford County / DCDT05.Guilford.com

> **Guilford County / DCDT05.Guilford.com** -- Processed 995M capture producing 2563159 timeline events in 2m48s. CloudRules found no detections. JSONL validation: OK.

### 10. Guilford County / ETFEDOS14.Guilford.com

> **Guilford County / ETFEDOS14.Guilford.com** -- Processed 1.3G capture producing 4730472 timeline events in 5m12s. CloudRules found no detections. JSONL validation: OK.

### 11. Guilford County / ETRDSTSTWV14.Guilford.com

> **Guilford County / ETRDSTSTWV14.Guilford.com** -- Processed 727M capture producing 2365520 timeline events in 2m7s. CloudRules found no detections. JSONL validation: OK.

### 12. Guilford County / ETRDSWSWV11.Guilford.com

> **Guilford County / ETRDSWSWV11.Guilford.com** -- Processed 572M capture producing 2553996 timeline events in 2m9s. CloudRules found no detections. JSONL validation: OK.

### 13. Guilford County / ETRDSWSWV11.Guilford.com

> **Guilford County / ETRDSWSWV11.Guilford.com** -- Processed 826M capture producing 3280996 timeline events in 2m52s. CloudRules found no detections. JSONL validation: OK.

### 14. Guilford County / gcadvauth.Guilford.com

> **Guilford County / gcadvauth.Guilford.com** -- Processed 906M capture producing 3644329 timeline events in 3m51s. CloudRules identified 306 detections across 300 events (306 NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(306) Tagged(detections) . Remote management software detected -- verify whether authorized for this endpoint. JSONL validation: OK.

### 15. Guilford County / LEDELL09235.Guilford.com

> **Guilford County / LEDELL09235.Guilford.com** -- Processed 2.0G capture producing 2340707 timeline events in 3m7s. CloudRules identified 33 detections across 33 events (15 NOTABLE, 18 LIKELY_NOTABLE). Top findings: Top(types:) BADLIST_HIT(18) REMOTE_ACCESS_SOFTWARE(15) . Remote management software detected -- verify whether authorized for this endpoint. JSONL validation: OK.

### 16. Guilford County / RDP-GATEWAY.personcounty.local

> **Guilford County / RDP-GATEWAY.personcounty.local** -- Processed 1.0G capture producing 2453703 timeline events in 2m15s. CloudRules identified 95 detections across 95 events (95 NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(95) Tagged(detections) . Remote management software detected -- verify whether authorized for this endpoint. JSONL validation: OK.

### 17. Lenoir County / LC911AD.lc911.local

> **Lenoir County / LC911AD.lc911.local** -- Processed 664M capture producing 1833789 timeline events in 2m1s. CloudRules identified 5 detections across 1 events (4 NOTABLE, 1 LIKELY_NOTABLE). Top findings: Top(types:) WINDOWS_DEFENDER_EXCLUSION_RULE(2) WINDOWS_DEFENDER_FEATURE_DISABLED(2) . Windows Defender configuration changes detected -- check for intentional security weakening. JSONL validation: OK.

### 18. Lenoir County / lcad03.lenoir.local

> **Lenoir County / lcad03.lenoir.local** -- Processed 823M capture producing 2660198 timeline events in 2m20s. CloudRules identified 9 detections across 4 events (8 NOTABLE, 1 LIKELY_NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(4) WINDOWS_DEFENDER_FEATURE_DISABLED(2) . Remote management software detected -- verify whether authorized for this endpoint. Windows Defender configuration changes detected -- check for intentional security weakening. JSONL validation: OK.

### 19. Lenoir County / LCRODCOTTDC.cott.local

> **Lenoir County / LCRODCOTTDC.cott.local** -- Processed 650M capture producing 2829012 timeline events in 2m22s. CloudRules identified 46 detections across 46 events (46 NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(46) Tagged(detections) . Remote management software detected -- verify whether authorized for this endpoint. JSONL validation: OK.

### 20. New Hanover County / SHER1Q85LS3.nhcgov.com

> **New Hanover County / SHER1Q85LS3.nhcgov.com** -- Processed 2.5G capture producing 3792572 timeline events in 5m2s. CloudRules identified 5 detections across 1 events (4 NOTABLE, 1 LIKELY_NOTABLE). Top findings: Top(types:) WINDOWS_DEFENDER_FEATURE_DISABLED(2) WINDOWS_DEFENDER_EXCLUSION_RULE(2) . Windows Defender configuration changes detected -- check for intentional security weakening. JSONL validation: OK.

### 21. Robeson County Sheriff / RCSO-HV01.robeson.domain

> **Robeson County Sheriff / RCSO-HV01.robeson.domain** -- Processed 976M capture producing 2379320 timeline events in 2m42s. CloudRules identified 7622 detections across 7613 events (7622 NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(7614) DATA_TRANSFER_TOOL(8) . Remote management software detected -- verify whether authorized for this endpoint. Data transfer tools present -- assess for potential exfiltration activity. JSONL validation: OK.

### 22. Robeson County Sheriff / RCSO-HV02.robeson.domain

> **Robeson County Sheriff / RCSO-HV02.robeson.domain** -- Processed 854M capture producing 1896600 timeline events in 2m12s. CloudRules identified 4838 detections across 4838 events (4830 NOTABLE, 8 LIKELY_NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(4830) BADLIST_HIT(8) . Remote management software detected -- verify whether authorized for this endpoint. JSONL validation: OK.

### 23. Robeson County Sheriff / RCSORMS.robeson.domain

> **Robeson County Sheriff / RCSORMS.robeson.domain** -- Processed 1.1G capture producing 2235370 timeline events in 2m40s. CloudRules identified 4224 detections across 4224 events (4224 NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(4207) DATA_TRANSFER_TOOL(17) . Remote management software detected -- verify whether authorized for this endpoint. Data transfer tools present -- assess for potential exfiltration activity. JSONL validation: OK.

### 24. Sleuth Kit Labs / FILESERVER-01.reynholm.local

> **Sleuth Kit Labs / FILESERVER-01.reynholm.local** -- Processed 516M capture producing 441889 timeline events in 39s. CloudRules identified 70 detections across 14 events (56 NOTABLE, 14 LIKELY_NOTABLE). Top findings: Top(types:) WINDOWS_DEFENDER_EXCLUSION_RULE(28) WINDOWS_DEFENDER_FEATURE_DISABLED(28) . Windows Defender configuration changes detected -- check for intentional security weakening. JSONL validation: OK.

### 25. Sleuth Kit Labs / RAGINGBULL.reynholm.local

> **Sleuth Kit Labs / RAGINGBULL.reynholm.local** -- Processed 1.3G capture producing 1347890 timeline events in 1m58s. CloudRules identified 152 detections across 84 events (132 NOTABLE, 20 LIKELY_NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(63) WINDOWS_DEFENDER_EXCLUSION_RULE(34) . Remote management software detected -- verify whether authorized for this endpoint. Windows Defender configuration changes detected -- check for intentional security weakening. JSONL validation: OK.

### 26. Sleuth Kit Labs / REYNHOLM-DC01.reynholm.local

> **Sleuth Kit Labs / REYNHOLM-DC01.reynholm.local** -- Processed 551M capture producing 888793 timeline events in 1m10s. CloudRules identified 47 detections across 15 events (39 NOTABLE, 8 LIKELY_NOTABLE). Top findings: Top(types:) WINDOWS_DEFENDER_EXCLUSION_RULE(16) WINDOWS_DEFENDER_FEATURE_DISABLED(16) . Windows Defender configuration changes detected -- check for intentional security weakening. JSONL validation: OK.

### 27. Town of Cornelius / DC00

> **Town of Cornelius / DC00** -- Processed 727M capture producing 4528720 timeline events in 5m25s. CloudRules identified 25 detections across 25 events (25 NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(25) Tagged(detections) . Remote management software detected -- verify whether authorized for this endpoint. JSONL validation: OK.

### 28. Town of Cornelius / DC02

> **Town of Cornelius / DC02** -- Processed 709M capture producing 4759934 timeline events in 5m45s. CloudRules identified 26 detections across 26 events (26 NOTABLE). Top findings: Top(types:) REMOTE_ACCESS_SOFTWARE(26) Tagged(detections) . Remote management software detected -- verify whether authorized for this endpoint. JSONL validation: OK.

## Aggregate Summary

- **Captures tested**: 28
- **Passed**: 28 / 28
- **Failed**: 0 / 28
- **Total events**: 82464322
- **Total CloudRules detections**: 20082
- **Total events tagged**: 19894
- **Cumulative processing time**: 6384.3s (~106 min)

### Disk Usage

- Starting free: 256Gi
- Minimum free during sweep: 241Gi
- Ending free: 257Gi

### Validation Method

- JSON validity: sampled 1,500 lines per file (head 500 / mid 500 / tail 500)
- Required fields checked: `datetime`, `timestamp_desc`, `message`
- Cleanup: cache, artifacts, and JSONL removed after each capture
