# L2TP/IPsec Client – C6 átjáró

**Kísérleti 0.1.0; tényleges HA OS-/VPN-/C6-teszt szükséges.**
Ez a kiegészítő a megadott adapter TCP-kapcsolatát közvetíti, nem az egész
Home Assistant forgalmát viszi VPN-re.

## Kezdés

Olvasd el a repository `README.md` és `SECURITY.md` fájlját. Az első kiadás
széles kernel-/eszközhozzáférést kér (`full_access`, `kernel_modules`, AppArmor
kikapcsolva); a Védett mód kikapcsolásával csak tudatosan indítsd el.

Először hagyd bekapcsolva a **Csak diagnosztika** módot. A naplóban a
`DIAGNOSTICS_OK` jelenti a sikeres alapellenőrzést, nem a VPN-kapcsolatot.
Utána add meg az adatokat, kapcsold ki a diagnosztikát, és indítsd újra.
A jelszavak csak itt, a HA-konfigurációban szerepeljenek, ne a GitHubon.

## Opciók

| Mező | Jelentés |
|---|---|
| `diagnostics_only` | `true`: kernel-/jogosultságpróba, nincs VPN-csatlakozás. |
| `vpn_server` | A Windowsban használt VPN-kiszolgáló IPv4-címe. |
| `vpn_username` | VPN-felhasználónév; tartománnyal együtt, ha a szolgáltató ezt adta. |
| `vpn_password` | A felhasználó jelszava. |
| `vpn_psk` | IPsec előre megosztott kulcs; nem azonos a felhasználó jelszavával. |
| `adapter_ip` | A C6 VPN-en elérhető IPv4-címe. |
| `adapter_port` | C6 TCP adatport, alapérték: `9999`. |
| `ppp_auth` | `mschapv2` az alapérték. `chap`, `pap`, `auto` csak a szerver követelménye szerint. |
| `legacy_compatibility` | Alapból `false`; `true` hozzáad MODP1024/3DES kompatibilitási ajánlatokat. |
| `mtu` | PPP MTU/MRU, alapérték `1400`, megengedett: 1280–1460. |
| `retry_delay` | Újrapróbálkozások közti várakozás, alapból 60 másodperc. |
| `max_retries` | Legfeljebb ennyi VPN-kapcsolódási ciklus egy addonindítás alatt; alapból 3. |
| `allowed_clients` | A belső TCP-átjáróhoz kapcsolódó forráscímek/CIDR-ek. |

A támogatott alapfolyamat IKEv1 + IPsec transport + L2TP + PPP. Nincs IKEv2,
OpenVPN, WireGuard, tinc, tanúsítványos IPsec vagy interaktív többfaktoros belépés.
Az első verzió egyetlen adaptert és egyszerre egy aktív TCP-kapcsolatot kezel.
Nem továbbít automatikus eszközfelismerést, multicastot vagy az adapter webfelületét.

## ebusd

Az addon Információ lapján látható **Hostnév** és a `9999` belső port kell:

```yaml
network_device: "ens:AZ_ADDON_TENYLEGES_HOSTNEVE:9999"
```

Az addon adatlapján a hálózati port publikálását hagyd üresen/kikapcsolva.
Ne állíts be hozzá routeres internetes porttovábbítást.

A saját HA-belső címtartomány alapból `172.30.32.0/23` szerepel az ACL-ben;
ha a napló szerint egy jogos belső kliens más címről érkezik, add hozzá annak
pontos `/32` címét. Ne engedélyezz találomra nagy hálózatokat. A proxy nem kínál
külön felhasználónév-/jelszóhitelesítést, ezért a hálózati elkülönítés és az ACL fontos.

## Gyakoribb hibák

**`PPP ... sikertelen`:** hiányzó kernel-PPP támogatás vagy eszköz-/capability
engedély. A Védett mód állapota és a napló `CONFIG_PPP` sora különbözteti meg
az okokat. Az, hogy a csomag telepíthető, nem bizonyítja a kernel kompatibilitását.

**IPsec policy-/iptables-hiba:** kernel XFRM-/ESP-/policy-match támogatás vagy
jogosultság hiánya. A kliens nem kapcsolja ki helyette a titkosítási védelmet.

**`NO_PROPOSAL_CHOSEN`:** a kiszolgáló nem fogadta el a titkosítási ajánlatot.
A szolgáltatóval egyeztetett régi szervernél kipróbálható a
`legacy_compatibility: true`. Ez gyengébb régi algoritmusokat is megenged;
ne kapcsold be általános hibaelhárításként, ha más a hiba.

**`AUTHENTICATION_FAILED` / `MS-CHAP authentication failed`:** PSK, felhasználó,
jelszó, tartomány vagy PPP-hitelesítési mód hibája. A kliens felismert hitelesítési
hiba után leáll, hogy ne folytasson felesleges belépési kísérleteket.

**`IPSEC_UP`, de nincs `VPN_UP`:** L2TP/PPP, UDP1701 forgalom, hitelesítési mód,
PPP-kernelcsatorna vagy a szerver címkiosztása vizsgálandó.

**`PROXY_READY`, de nincs `C6_TCP_CONNECTED`:** ebusd még nem kapcsolódott,
rossz addonhostnév/ACL, rossz adaptercím/port, távoli útvonal/tűzfal vagy foglalt
adapter lehet az ok. A proxy szándékosan nem nyit időszakos külön tesztkapcsolatot
az adapterhez.

**TCP működik, de eBUS-időtúllépések vannak:** a VPN késleltetését és ingadozását,
valamint az ebusd naplóját is vizsgálni kell. A TCP-kapcsolat önmagában nem
garantálja az eBUS protokoll időzítéseinek megfelelő működést.

## Biztonság és üzemeltetés

A kimenő adapterkapcsolat a PPP-eszközhöz van kötve. A saját konténerhálózaton
belüli tűzfalszabályok tiltják a titkosítás nélküli L2TP-t és a VPN-en kívüli
adapter-TCP-forgalmat. Ezek implementált védelmek, de teljes éles hálózati
ellenőrzésük még nem történt meg ebben a kiadásban.

A jelszómezők elrejtése a felületen nem titkosítja automatikusan a HA tárolt
beállításait. A HA-mentéseket kezeld titkos adatként. A napló megosztása előtt
ellenőrizd a tartalmát akkor is, ha az addon kitakarja az ismert hitelesítési adatokat.

Első próba: kézi indítás, Watchdog kikapcsolva. Automatikus indulást csak
sikeres helyszíni teszt után állíts be. A részletes forrás- és tesztlista a
repository README és TEST_REPORT fájljában található.
