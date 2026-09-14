# Használat – 0.2.1

## Alapellenőrzés

`diagnostics_only: true` mellett csak TUN- és motorellenőrzés történik,
VPN-hitelesítési kísérlet nélkül. A sikeres diagnosztika nem bizonyítja a
szerverrel való protokoll-kompatibilitást. A 0.2.x már nem használ `/dev/ppp`-t.

A 0.2.0-ról frissítés részletes menete a repository gyökerében az `UPGRADE.md`.

## Hitelesítés

A `vpn_server` mezőben számszerű IPv4-cím szükséges, nem URL vagy domainnév.
A `vpn_username`, `vpn_password` és `vpn_psk` külön mező. A titkokat a HA
beállítófelületén add meg, ne forrásfájlban. A `ppp_auth` maradjon `mschapv2`,
a `legacy_compatibility` pedig `false`: más mód nincs megvalósítva.
Az MTU alapértéke 1400. A próbálkozási korlátot az első teszthez 1-re állítsd.
Az MTU módosítása nem célzott megoldás egy korai IKE-hibára.

## Működési módok

| `connection_mode` | Kötelező céladat | Mi történik? |
|---|---|---|
| `vpn_test` | Nincs | VPN-bejelentkezés, VPN_TEST_OK, rendezett leállás. |
| `discover` | `discovery_networks` | VPN-bejelentkezés, egyszeri TCP-keresés, naplózás, leállás. |
| `proxy` | `adapter_ip` | VPN-bejelentkezés, az ismert adapterhez egyklienses TCP-átjáró. |

Az alapérték `proxy`, így a korábbi beállításokat nem kezdi el önkényesen
keresési módra váltani. `vpn_test` és `discover` módban az `adapter_ip`
üresen hagyható, és egy korábban megadott értéket a program figyelmen kívül hagy.
A `diagnostics_only: true` felülírja mindhárom módot: ilyenkor továbbra is
csak helyi előellenőrzés fut.

## IKE-hiba vizsgálata

Kapcsold be az `ike_trace` opciót, válassz `vpn_test` módot, és indítsd újra.
Az observer az addon külső interfészén csak az adott szerverhez/szervertől
menő UDP 500/4500 forgalomból az IKEv1-fejlécek metaadatait naplózza.
A kimenetben nem szerepelnek IKE-cookie-k, ID-k, HASH-ok, PSK-k vagy jelszavak.
A folyamat nem készít PCAP-fájlt. A forgalmi metaadatok és a VPN-es címek
ettől még érzékeny hálózati információk lehetnek.

Példa (nem tényleges mérés):

```text
IKE_TX udp=51234->500 exchange=MainMode encrypted=0 first_payload=SA bytes=...
IKE_RX udp=500->51234 exchange=MainMode encrypted=0 first_payload=SA bytes=...
IKE_TRACE_SUMMARY tx=3 rx=2 rx4500=0
```

`tx>0, rx=0`: az addon külső interfészén nem láttunk a megfigyelt kéréshez
illeszkedő IKE-választ. Lehet cím-/útvonal-/tűzfal-/NAT-hiba, de a szerver
csendes elutasítása is. Ez nem bizonyítja, hogy a kiszolgálóhoz a kérés
eljutott, és nem bizonyítja, hogy a hálózat az egyetlen hiba.

`rx>0`: legalább egy, IKE-cookie szerint illeszkedő válasz látszott. Ez nem
jelent sikeres hitelesítést, és nem bizonyítja az összes további UDP-forgalom
elérhetőségét. A pontos egyeztetési hibához a szervernapló is szükséges lehet.

`IKE_TRACE_UNAVAILABLE`: a passzív fejlécfigyelés nem indult; ez nem jelenti
azt, hogy a VPN sem működhet. A VPN-próba ilyenkor folytatódik.
Az observer IPv4 töredékeket nem állít össze; megfigyelése nem teljes PCAP.

Hasonlítsd össze egy működő Windows-kapcsolattal ugyanazon internetkapcsolat
mögül, külön-külön indítva. A kísérleti kliens és a szerver algoritmuslistája
is eltérhet. Ne állíts át kriptográfiát vagy nyiss bejövő internetes portot
pusztán az időtúllépés miatt. A szolgáltatói naplóban az IKE/Phase 1 és NAT-T
eseményeket érdemes a kliens próbájának időpontjához illeszteni.

## Távoli hálózat keresése

Saját/engedélyezett hálózatból 1–8 CIDR adható meg, összesen legfeljebb
1024 címmel, csak RFC1918 vagy 100.64.0.0/10 tartományban. Nincsenek átfedő
hálózatok, és a keresési tartomány nem tartalmazhatja a VPN-szerver címét,
illetve nem ütközhet az addon Docker-hálózatával. A kereső nem találgat
/24 hálózatot a kapott VPN-címből, és nem pásztázza végig a szolgáltató hálózatát.

A VPN-poolból kapott cím nem azonos a távoli LAN hálózatával. A LAN CIDR-jét
a hálózat üzemeltetőjétől vagy a működő Windows-kapcsolat útvonalaiból lehet
meghatározni; az utóbbi sem feltétlenül sorol fel mindent, például default
route esetén. A keresés a rosszul megadott, de megengedett CIDR-t is a VPN
felé fogja küldeni, ezért a pontos tartomány megadása az üzemeltető feladata.

A `discovery_ports` legfeljebb 8 TCP-portot fogad el; alapérték 9999,80,443.
Legfeljebb 8 párhuzamos hostvizsgálat és globálisan 20 kapcsolatindítás/mp van,
portonként 1 másodperces várakozással. Egy sikeres induláskor csak egyszer fut.
A keresés nem küld alkalmazásadatot, HTTP-kérést vagy eBUS-parancsot. A TCP
kapcsolatfelvétel rövid időre így is lefoglalhat egy kapcsolati helyet,
ezért az ebusd-t érdemes leállítva tartani a keresés idejére.

Az összes keresési kapcsolat TUN-interfészhez és VPN-forráscímhez kötött.
Nincs LAN-os tartalékút. A keresés sikeres VPN előtt nem indul el.
A saját kiosztott VPN-címet és normál alhálózatnál a network/broadcast címet
kihagyja. A kapott TCP-válaszokat naplózza; a `refused_tcp` zárt/elutasított
portot jelent, a válasz akár hálózati tűzfaltól is származhat. Az elérhetetlen,
ICMP-t vagy TCP-t szűrő, illetve a vizsgált portokon nem válaszoló eszközök
hiányozhatnak a listából. Ez **nem teljes hálózati eszközleltár**.

A 9999-es porton válaszoló cím `C6_CANDIDATE` jelzést kap, de a program
nem állítja, hogy biztosan eBUS-adapter. Azonosítás után a címet kézzel kell
megadni. Routed VPN-en MAC-cím/gyártólista nem áll rendelkezésre ettől a keresőtől.

## ebusd / másik Home Assistant-gép

`proxy` módban az addon belső TCP-portja 9999. Ugyanazon HA-n az addon
adatlapján látható belső hostnevet használd:

```yaml
network_device: "ens:AZ_ADDON_BELSO_HOSTNEVE:9999"
```

Másik HA-géphez a VPN-addon Hálózat részében tudatosan közzé kell tenni
például a 9999-es portot, az `allowed_clients` listába pedig fel kell venni
a másik gép helyi IPv4-címét `/32` végződéssel. Ekkor az ebusd a VPN-addon
HA-gépének helyi címéhez csatlakozik, nem a belső addonhostnévhez.
Ne nyiss internet felőli továbbítást ehhez. A helyi TCP-kapcsolat nem TLS.
A proxy egyszerre egy kliensnek enged adapterkapcsolatot.

`C6_TCP_CONNECTED` csak valódi adapter TCP-kapcsolatot jelez;
`PROXY_READY` önmagában nem igazolja az adapter elérhetőségét.
