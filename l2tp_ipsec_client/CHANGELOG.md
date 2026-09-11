# 0.1.0

Első kísérleti változat, nem éles üzemi kiadás.

- Alpine 3.23 alap, strongSwan, xl2tpd és pppd.
- Home Assistant GUI-konfiguráció, magyar és angol mezőleírások.
- Első indításkor PPP-/XFRM-/policy-kernel- és jogosultságpróba.
- Saját addonhálózat és egyetlen C6 TCP-célpont közvetítése.
- Nincs host-network, HA-default-route csere vagy HA-DNS módosítás.
- PPP-hez kötött kimenő socket és konténeren belüli forgalmi védelmek.
- Korlátozott újracsatlakozás, hitelesítési hiba utáni leállás.
- Hitelesítési adatok privát fájlokban, ismert értékek kitakarása a naplóban.
- Offline tesztek és opcionális GitHub Actions buildellenőrzés.

Még ellenőrizendő: Docker-build, Supervisor-telepítés, HA OS kernel, VPN-szerver
kompatibilitás, C6 adatkapcsolat, valódi tunnel-leállási/újracsatlakozási tesztek.
