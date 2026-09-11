# L2TP/IPsec C6 átjáró Home Assistanthoz – 0.2.0

**Kísérleti forráscsomag. Nem igazolt még valódi HA OS-en vagy Giganet VPN-szerverrel.**

Ez a változat a `CONFIG_PPP=n` korlát megkerülésére készült: a veepin L2TP/IPsec-könyvtárával a PPP-t a felhasználói program kezeli, nem a Linux kernel. TUN-hozzáférés továbbra is szükséges.

```text
ebusd addon → C6 átjáró addon TCP 9999 → L2TP/IPsec VPN → távoli C6 TCP-port
```

Nem általános VPN az összes HA-komponens számára. Csak a beállított adapter egy TCP-portjához közvetít kapcsolatot. A VPN és az útvonalak a saját konténer hálózati névterében maradnak; a HA gazdarendszerének default route-ját vagy DNS-ét nem módosítja.

## Már telepítetted a 0.1.0-t?

A teljes frissítési leírás: **[UPGRADE.md](UPGRADE.md)**. Ugyanazt a GitHub-tárolót és `l2tp_ipsec_client` azonosítót használd. Ne csak a verziószámot írd át: az egész csomagot cseréld.

## Első telepítés

A tároló teljes tartalma kerüljön a saját nyilvános GitHub-repositoryd gyökerébe. A `repository.yaml` maradjon gyökérszinten, mellette a `l2tp_ipsec_client/` mappa. A repository címét a Home Assistant alkalmazás-/bővítményáruházában a Tárolók menüben add hozzá; nem HACS-integráció.

A telepítési és beállítási útmutató az addonban is megjelenő **[DOCS.md](l2tp_ipsec_client/DOCS.md)**.

## Követelmények és korlátok

- HA Supervisor addonrendszer; a manifest `amd64` és `aarch64` architektúrát engedélyez. Ezek nem tesztelt kompatibilitási tanúsítások; 32 bites ARM nincs engedélyezve.
- `/dev/net/tun`, `NET_ADMIN`, `NET_RAW`. Nincs `full_access`, kernelmodul-betöltés vagy host hálózat. Az AppArmor engedélyezett.
- IPv4 VPN-szervercím és IPv4 adaptercím. Ebben a verzióban szervernév nem adható meg.
- IKEv1 + PSK, NAT-T, L2TP és MS-CHAPv2. A szerver pontos titkosítási/hitelesítési kompatibilitását tesztelni kell. PAP/CHAP és a régi `legacy_compatibility` kapcsoló nincs implementálva.
- Egyszerre egy C6-kliens; nincs önálló eBUS-lekérdezés vagy automatikus adapterpoll.

A felhasználónév, jelszó és PSK csak a Home Assistant addonbeállításaiba kerüljön. **Nyilvános GitHub-fájlba, Actions-titokba vagy hibajegybe nem kell és nem szabad beírni.**

## Ellenőrzések

A csomag készítésekor 42 Python-teszt és 2, csak szabványos könyvtárat használó Go-bemenetellenőrzési teszt sikeres volt. A Python-csomagban valódi helyi TCP-relétesztek is szerepelnek, de a TUN/VPN-események szimuláltak. **A teljes veepin-motor lefordítása, Docker-build, HA-telepítés és Giganet-kapcsolat nem történt meg.** Részletek: [TEST_REPORT.md](TEST_REPORT.md).

A `.github/workflows/build.yml` feltöltés után elvégezheti a teljes amd64 Docker-buildet és a jelszó nélküli TUN-diagnosztikát GitHub Actions alatt. A sikeres CI sem jelenti a Giganet-kapcsolat igazolását.

## Források

- Home Assistant konfiguráció: https://developers.home-assistant.io/docs/apps/configuration/
- Home Assistant belső kommunikáció: https://developers.home-assistant.io/docs/apps/communication/
- veepin L2TP-motor: https://github.com/xen0bit/veepin
- veepin L2TP-dokumentáció: https://github.com/xen0bit/veepin/blob/main/doc/usage/l2tp.md
- Rögzített upstream commit: `6c37e3691c326e54956cea042e2df67d3717e7a4` (`v0.9.6`).

A biztonsági tudnivalókat a [SECURITY.md](SECURITY.md), a licenceket a [NOTICE.md](NOTICE.md) foglalja össze.
