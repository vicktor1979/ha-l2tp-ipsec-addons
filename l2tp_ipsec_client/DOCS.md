# L2TP/IPsec C6 átjáró – 0.2.0

**KÍSÉRLETI. A teljes motor-build, a HA OS futtatás és a Giganet-kapcsolat még nincs helyben igazolva.**

A `CONFIG_PPP=n` kernelhez készült alternatív motor. Nem használ `pppd`-t, `xl2tpd`-t, `/dev/ppp`-t vagy kernel-IPsec-et. A veepin a protokollokat a programban kezeli; a Linux `/dev/net/tun` interfésze továbbra is kell. A saját konténerhálózatban működik, és csak az adapter egy TCP-portját közvetíti.

## Első indítás

Készíts mentést, az automatikus indítást és a Watchdogot hagyd kikapcsolva. A 0.1.0-hoz képest megszűnt a teljes hardver- és kernelmodul-hozzáférés igénye; az AppArmor engedélyezett. **Védett móddal kezdd a próbát.** Ha a TUN-próba jogosultsági hibával leáll, őrizd meg a pontos hibakódot; ne bővítsd találomra a jogosultságokat.

Maradjon `diagnostics_only: true`. A többi mező titkos adata üresen hagyható. Indítás után a `TUN_OK`, `ENGINE_OK`, `DIAGNOSTICS_OK` jelzéseket keressük. A `PPP_KERNEL_NOT_REQUIRED` azt jelzi, hogy a régi hiányzó kernel-PPP már nem feltétel.

Ez **nem sikeres VPN-teszt**. A jelszó nélküli ellenőrzés után az addon várakozva fut tovább. A diagnosztikai TUN a vizsgálat végén megszűnik.

## VPN-beállítások

Az alábbi **teljes minta** példacímeket és helykitöltőket tartalmaz. A valódi titkokat kizárólag a HA addon beállításaiba írd. Az idézőjeles szövegmezőket a felületen kényelmesebb kitölteni; YAML esetén ügyelj az idézőjelek és visszaperjelek helyes escape-elésére.

```yaml
diagnostics_only: false
vpn_server: "203.0.113.15"
vpn_username: "SAJAT_VPN_FELHASZNALONEV"
vpn_password: "SAJAT_VPN_JELSZO"
vpn_psk: "SAJAT_IPSEC_MEGOSZTOTT_KULCS"
adapter_ip: "192.168.50.60"
adapter_port: 9999
ppp_auth: mschapv2
legacy_compatibility: false
mtu: 1400
retry_delay: 60
max_retries: 3
allowed_clients:
  - "172.30.32.0/23"
  - "127.0.0.1/32"
```

A `vpn_server` a Windows VPN-beállításában szereplő VPN-szerver IPv4-címe, nem a C6 címe. A `vpn_psk` a Windowsban külön megadott L2TP/IPsec megosztott kulcs. Az `adapter_ip` a C6 belső, VPN-en elérhető IPv4-címe. A szervercímhez ebben a verzióban nem használható domainnév vagy URL.

A `ppp_auth` és `legacy_compatibility` mezők a 0.1.0-ról frissítés miatt megmaradtak a sémában. **Csak `mschapv2` és `false` támogatott**; a többi érték egyértelmű konfigurációhibával leáll, nem kerül csendben figyelmen kívül hagyásra.

A kliens IKEv1 PSK + NAT-T + L2TP + MS-CHAPv2 kapcsolatot kér. A Giganet szerverének pontos IKE/ESP ajánlataival való egyezés még nem ellenőrzött. A dokumentált upstream együttműködési teszt másik szerverrel történt; a Windows sikeres kapcsolata nem bizonyítja automatikusan ennek a kliensnek a kompatibilitását.

A külső tűzfalnak a VPN-szerver felé a kapcsolat UDP 500 és 4500 forgalmát engednie kell. **Bejövő internetes porttovábbítást ne készíts** sem a proxyhoz, sem a C6-hoz. A kiszolgálónak továbbítania kell a VPN-kliens forgalmát az adapter hálózatába.

## Mit jelentenek a naplójelzések?

| Jelzés | Amit valóban igazol |
|---|---|
| `PPP_KERNEL_NOT_REQUIRED` | Az új program nem kernel-PPP-t használ. |
| `TUN_OK` | A konténerben a TUN nyitás/létrehozás és a socket interfészhez kötése sikerült. |
| `ENGINE_OK` | A 0.2.0 motor elindítható; még nem tárcsázott. |
| `DIAGNOSTICS_OK` | A fenti helyi alapellenőrzések sikeresek. |
| `VPN_UP` | A motor szerint felépült a VPN és van kiosztott IPv4-cím. |
| `ROUTE_OK` | Az adapter /32 útvonala bekerült a konténer útválasztásába. |
| `PROXY_READY` | A helyi TCP-átjáró figyel; ez még nem bizonyít adapterelérést. |
| `C6_TCP_CONNECTED` | Egy engedélyezett kliens kérésére a C6 TCP-portjához kapcsolódott a proxy. |

Az eBUS működését ezután külön az ebusd saját naplójában kell ellenőrizni. A proxy nem értelmezi az eBUS-kereteket és nem indít önálló buszforgalmat.

## ebusd ugyanazon a Home Assistanton

A proxy belső addonhostnevét használd. A Supervisor az addonok közötti belső DNS-t biztosítja; az addon azonosítójának aláhúzásai a DNS-névben kötőjellé alakulnak. Az adatlap szerinti hostnevet ellenőrizd, a napló mintája csak támpont.

```yaml
network_device: "ens:AZ_ADDON_BELSO_HOSTNEVE:9999"
```

Ez konfigurációrészlet az **ebusd** addonhoz. Itt nem a VPN-szerver címét kell megadni. Az ebusd többi, már működő C6-beállítása maradjon változatlan. Az alapértelmezett `allowed_clients` a szokásos belső HA-hálózatot és a loopbacket engedélyezi. Ha a naplóban más belső forráscím elutasítása látszik, csak az indokolt konkrét címet vedd fel.

## ebusd másik gépen – például ARM HA → amd64 HA

Külön HA-rendszerek között a belső addonhostnév nem használható. Az amd64 HA-n az addon **Konfiguráció → Hálózat** részén tedd közzé a konténer `9999/tcp` portját például a gazdagép `9999` portján. Ez alapból üres, azaz nincs közzétéve.

Az addon `allowed_clients` listájához add hozzá az ebusd-t futtató másik HA **helyi IP-címét /32 végződéssel**, például:

```yaml
allowed_clients:
  - "172.30.32.0/23"
  - "127.0.0.1/32"
  - "192.168.1.20/32"
```

A másik gép ebusd-beállítása a példában:

```yaml
network_device: "ens:192.168.1.30:9999"
```

Itt `192.168.1.30` a VPN-addont futtató HA helyi címe; `192.168.1.20` az ebusd-t futtató HA helyi címe. **Mindkettő példa, írd át.** Ha a gazdagép portja foglalt, használj másik külső portot, és az ebusd-ben azt add meg.

Az átjáró TCP-oldalán nincs külön jelszavas hitelesítés vagy TLS. Csak megbízható LAN-on, konkrét forráscím engedélyezésével használd. A routeren ne irányíts hozzá WAN-portot. A köztes NAT/tűzfal megváltoztathatja a forráscímet; az elutasítási naplóból a tényleges cím látható.

## Megszakadás és újracsatlakozás

A C6 felé nyitott socket kötelezően a VPN TUN-interfészéhez és kiosztott IP-címéhez kötött. Sikertelen kötéskor nincs közvetlen LAN-os visszaesés. Kiegészítésként az adapter /32 címéhez a konténerben magasabb metrikájú tiltó útvonal marad, amely élő VPN nélkül megakadályozza a hagyományos alapútvonal használatát ehhez a címhez.

A motor aktív L2TP életjelvizsgálatot kér. VPN-leálláskor a proxy bezárja a TCP-kapcsolatokat. Új VPN felépülése után az ebusd-nek újra kell kapcsolódnia; megszakadt TCP-adatfolyamot nem próbál észrevétlenül új kapcsolatba folytatni.

Az automatikus próbálkozások száma egy addonindításon belül legfeljebb `max_retries` (alapból 3), köztük `retry_delay` várakozással. A motor által hitelesítési hibaként azonosított válasznál a program azonnal leáll, nem próbálkozik újra. Egy általános kézfogási hiba lehet szerver-kompatibilitási probléma is; az nem mindig azonosítható hibás jelszóként.

## Hibakeresés

- **Még `/dev/ppp` hiba jelenik meg:** régi kép fut; ellenőrizd a telepített verziót és a GitHubon a teljes frissített forrást.
- **`/dev/net/tun` hiányzik:** az eszközátadás vagy a host TUN-támogatása hiányos. Ez nem PPP-hiba.
- **TUN `errno=1` vagy `errno=13`:** konkrét eszköz-/AppArmor-/capability-engedélyezési probléma. A 0.2.0 naplóját és a Supervisor hibáját vizsgáld, ne adj általánosan teljes hardverhozzáférést.
- **Build/Go-fordítási hiba:** a teljes hibás buildlépés naplója szükséges. VPN-adatok a fordításhoz nem kellenek.
- **IKE/NAT-T/időtúllépés:** lehet hálózat, szerveroldali engedélyezés vagy algoritmus-eltérés; ebből még nem következik rossz felhasználói jelszó.
- **`VPN_UP` megvan, C6 nem érhető el:** adaptercím/port, VPN-oldali útvonal és tűzfal, illetve az adaptert már használó másik ebusd ellenőrzendő.
- **Proxy elutasítja a klienst:** az `allowed_clients` és az egyszerre egy C6-kapcsolat korlátja ellenőrzendő.

A naplókat megosztás előtt kézzel is nézd át. Jelszót, PSK-t, teljes `options.json` fájlt vagy éles konfigurációs képernyőképet ne küldj.

## Források

- https://developers.home-assistant.io/docs/apps/configuration/
- https://developers.home-assistant.io/docs/apps/communication/
- https://github.com/xen0bit/veepin/blob/main/doc/usage/l2tp.md
- https://github.com/xen0bit/veepin/blob/main/l2tp/l2tp.go
- https://github.com/john30/ebusd/wiki/2.-Run
