# Frissítés 0.2.0 → 0.2.1

Készíts mentést. Állítsd le az addont, és tesztelés alatt tartsd kikapcsolva
az automatikus indítást és a Watchdogot. A Védett mód maradhat a 0.2.0
sikeres TUN-próbájánál használt állapotban; a 0.2.1 nem kér új jogosultságot.

A teljes csomagot töltsd fel ugyanabba a GitHub-repositoryba, majd az
áruház újraellenőrzése után frissíts 0.2.1-re. Ne csak a verziószámot írd át.
Új fájl: `l2tp_ipsec_client/vpn_tools.py`; a Dockerfile is módosult.
A `.github/workflows/build.yml` fájlt is frissítsd.

A hálózati protokollmotor megvalósítása változatlan. A helper verziójelzése
0.2.1, hogy az addon az összekeveredett buildfájlokat észlelhesse.

## Első próba a jelenlegi IKE időtúllépéshez

A meglévő VPN-hitelesítési adatok maradjanak meg. A következő **részletet**
állítsd be a konfigurációban, ne töröld a többi szükséges mezőt:

```yaml
diagnostics_only: false
connection_mode: vpn_test
adapter_ip: ""
ike_trace: true
max_retries: 1
```

Ekkor nincs célhálózat-keresés és nincs proxy. A VPN-felépülés után
`VPN_TEST_OK` jelenik meg, és a program szándékosan befejeződik.
Ha az IKE elakad, `IKE_TX`, `IKE_RX`, `IKE_TRACE_SUMMARY` segít különválasztani
az észlelt válasz nélküli próbát az egyeztetés későbbi elakadásától.
A megfigyelt válasz önmagában még nem hitelesített válasz.

## Keresés sikeres VPN után

A távoli helyi hálózat valódi CIDR-je szükséges. A VPN-kliens kiosztott címe
nem feltétlenül ennek a hálózatnak a címtartományából származik.
**A 192.168.50.0/24 alább csak példa, nem a te hálózatod azonosítása.**

```yaml
diagnostics_only: false
connection_mode: discover
adapter_ip: ""
discovery_networks:
  - "192.168.50.0/24"
discovery_ports:
  - 9999
  - 80
  - 443
ike_trace: false
max_retries: 1
```

Csak olyan távoli hálózatot adj meg, amelyet jogosult vagy vizsgálni.
A sikeres keresés egyszer lefut, a proxy nem indul el, a VPN lezárul,
a leállás ekkor rendeltetésszerű. A naplóban keresd a `SCAN_HOST`,
`C6_CANDIDATE`, `SCAN_DONE` sorokat. A `9999` nyitott port csak jelölt,
nem bizonyítja az adapter típusát. A program nem választ címet automatikusan.

## Visszatérés az átjáróhoz

Az azonosított C6-címet az `adapter_ip` mezőbe írd, és állítsd:

```yaml
connection_mode: proxy
ike_trace: false
```

Az addon alapportja nem változott. Ne tedd ki az internetre. Az ebusd
beállítását csak a tényleges C6-cím azonosítása és a VPN-siker után módosítsd.
