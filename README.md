# L2TP/IPsec – Home Assistant addon

**0.1.0 · kísérleti · amd64 · L2TP/IPsec + PSK + felhasználónév/jelszó**

A cél egy távoli eBUS C6 adapter elérése az ebusd addonból a meglévő
L2TP/IPsec VPN-en keresztül. Nem kell hozzá külön Windows-gép.

Ez új implementáció, amelyhez az `ubergarm/l2tp-ipsec-vpn-client` projekt
adta a kiinduló ötletet. Nem az elavult Docker-kép változatlan becsomagolása,
és nem tinc- vagy WireGuard-kliens.

> **Tesztelési állapot:** a Python-kód és a konfigurációgenerálás offline
> ellenőrzése megtörtént. A Docker-kép buildje, a Home Assistant OS-en történő
> indulás és a tényleges VPN-/C6-kapcsolat ebben a kiadásban még nincs igazolva.
> Első indításkor az addon csak diagnosztikát végez. Lásd: `TEST_REPORT.md`.

## Felépítés

```text
ebusd addon
       │ a HA belső addonhálózata, TCP 9999
       ▼
L2TP/IPsec Client – C6 átjáró
       │ saját hálózati névtér, L2TP/IPsec kapcsolat
       ▼
VPN-szerver → távoli C6 adapter TCP-portja
```

Az addon **nem általános VPN-útválasztó a teljes HA számára**. Kizárólag a
beállított adapter TCP-kapcsolatát közvetíti. Nem ad hozzá útvonalat a HA
gazdarendszeréhez, nem állítja át a HA DNS-ét, és nem módosítja az alapértelmezett
internetes átjárót. A saját hálózati névtér nem jelent teljes biztonsági
elszigetelést: az első prototípus emelt kernel-/hardverjogosultságot kér.

## GitHubra feltöltés

1. Hozz létre egy új, nyilvános GitHub repositoryt, például
   `ha-l2tp-ipsec-addons` néven. A fájlokban nincsenek valódi bejelentkezési adatok.
2. Csomagold ki a kapott ZIP-et. A kicsomagolt mappa **tartalmát** töltsd fel a
   repository gyökerébe az **Add file → Upload files** felületen.
   Teljesen üres tárolónál az **uploading an existing file** hivatkozás vezet ide.
3. A gyökérben közvetlenül látszódjon a `repository.yaml` és a
   `l2tp_ipsec_client` mappa. Ne magát a ZIP-et töltsd fel, és ne legyen plusz
   `ha-l2tp-ipsec-addons` mappaszint.
4. Mentsd a fájlokat (**Commit changes**).

A `repository.yaml` szándékosan nem tartalmaz felhasználónévhez kötött URL-t.
A feltöltés előtt nem szükséges átírni. A `.github/workflows/build.yml` opcionális
ellenőrzést futtat GitHub Actionsben; nem publikál képet, és nem kér VPN-titkokat.
A HA a Dockerfile-ból helyben építi fel az addont.

## Telepítés a Home Assistantban

**Beállítások → Bővítmények / Alkalmazások → Áruház → ⋮ → Tárolók**

Add hozzá a saját repositoryd címét:

```text
https://github.com/SAJAT_FELHASZNALONEV/ha-l2tp-ipsec-addons
```

Frissítsd az áruházat, nyisd meg az **L2TP/IPsec Client – C6 átjáró** elemet,
és telepítsd. Ez a Supervisor/HA OS addonrendszerét igényli; HACS-ba nem való.

## Első indítás: csak diagnosztika

Előbb készíts HA-mentést, és olvasd el a `SECURITY.md` fájlt.

A kísérleti addon `full_access: true`, `kernel_modules: true` és
`apparmor: false` beállítású. Emiatt az addon adatlapján a **Védett mód /
Protection mode** kikapcsolása szükséges a tényleges kernel-/eszközhozzáféréshez.
Ez nem pusztán egy hálózati engedély: széles hardver-/kerneljogosultságot ad.
Csak saját, átnézett kódnál és a kockázat ismeretében használd.

A konfigurációban egyelőre maradjon:

```yaml
diagnostics_only: true
```

A VPN-adatok ebben az üzemmódban üresek maradhatnak. Indítsd el az addont,
és nyisd meg a naplóját.

A sikeres alapellenőrzést ez jelzi:

```text
PPP_KERNEL_OK
XFRM_POLICY_OK
DIAGNOSTICS_OK
```

A diagnosztika a meglévő kernelmodulok betöltését, egy rövid életű PPP-interfész
létrehozását és egy forgalomhoz nem kapcsolt tűzfallánc kipróbálását végzi.
**Nem kapcsolódik a VPN-hez, és nem ellenőrzi a jelszavak helyességét.**
A sikeres ellenőrzés után a folyamat futva marad, de VPN-kapcsolat még nincs.

Ha PPP-/XFRM-/policy-hiba jelenik meg, először azt kell tisztázni. A konténer
nem tud a HA OS kerneléből hiányzó drivert önmagában pótolni. Ha a HA OS-ben
nincs megfelelő támogatás, ehhez a megoldáshoz más kernel vagy külön Linux
rendszer szükséges; a diagnosztika sikerét előre nem szabad feltételezni.

## VPN és C6 beállítása

Sikeres diagnosztika után a **HA addon konfigurációjában** add meg a valódi
adatokat, majd állítsd át a `diagnostics_only` értékét. **Ne a GitHubon szerkeszd
be a jelszavakat!** A címek lent csak dokumentációs példák.

```yaml
diagnostics_only: false
vpn_server: "203.0.113.20"
vpn_username: "SAJAT_VPN_FELHASZNALO"
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

A `vpn_server` a Windowsban használt VPN-kiszolgáló **IPv4-címe**. A `vpn_psk`
a Windows L2TP/IPsec speciális beállításainál megadott előre megosztott kulcs.
Az `adapter_ip` ettől különböző, VPN-en át elérhető C6-cím. Az első verzió nem
fogad el DNS-nevet vagy IPv6-címet ebben a két mezőben.

A maradék beállítás magyarázata a `l2tp_ipsec_client/DOCS.md` fájlban és az addon
Dokumentáció lapján található. Mentsd a konfigurációt, és indítsd újra az addont.

## ebusd beállítása

A VPN-addon **Információ / Info** lapján másold ki a **Hostnév / Hostname** mezőt.
A sikeres VPN-indulás naplója is kiír egy ebusd mintát; a hostnevet ellenőrizd
az adatlapon. GitHubról telepítve a repositoryhoz tartozó előtag változó.

Például, kizárólag szemléltetésként:

```yaml
network_device: "ens:12345678-l2tp-ipsec-client:9999"
```

A tényleges `12345678-l2tp-ipsec-client` helyett **a saját addonod hostneve kell**.
Nem a VPN-szerver és nem közvetlenül a C6 IP-címét adod meg az ebusd-nek.
A Vaillant integráció továbbra is a meglévő ebusd addonhoz kapcsolódik.

Az addon hálózati beállításainál a 9999-es port LAN-ra publikálását hagyd
kikapcsolva. A HA belső addonhálózatában így is használható. Az alap hozzáférési
lista a szokásos `172.30.32.0/23` belső címtartományt és a loopbacket engedi;
eltérő, egyedileg kialakított addonhálózatnál ezt módosítani kell.

Naplójelzések:

| Jelzés | Amit igazol |
|---|---|
| `DIAGNOSTICS_OK` | Az alap kernel-/jogosultságpróbák sikerültek; nincs VPN-próba. |
| `IPSEC_UP` | Létrejött az IPsec transport SA. |
| `VPN_UP` | Létrejött a PPP-interfész és kapott IPv4-címet. |
| `PROXY_READY` | Elindult a belső TCP-átjáró; az adapter elérése még nem bizonyított. |
| `C6_TCP_CONNECTED` | Egy tényleges klienskapcsolat során az adapter TCP-portja válaszolt. |

Az eBUS-jel és a Vaillant-adatok helyességét külön az **ebusd naplójában** kell
ellenőrizni. A TCP-siker önmagában nem bizonyítja a kazánkommunikáció működését.
Kezdetben csak olvasással tesztelj; működő fűtési vezérlést ne cserélj le egy
igazolatlan VPN-es kapcsolatra.

## Frissítés / visszaállás

Új kiadásnál a forrásfájlokat és az addon `config.yaml` fájljában a `version`
értékét is frissítsd a GitHubon, majd keress frissítést a HA áruházában.
Az automatikus indítást csak sikeres helyszíni teszt után kapcsold be.
Az első próbákhoz a Watchdogot hagyd kikapcsolva, hogy ne kerülje meg a
beépített próbálkozási korlátot.

Leállításkor a saját PPP-/IPsec-kapcsolat és proxy leáll. A HA útvonalait
nem kellett módosítani, tehát azokat nem kell helyreállítani. A diagnosztika
által betöltött, más folyamatokkal is megosztható kernelmodulokat az addon
szándékosan nem távolítja el.

## Források

- Kiinduló projekt: https://github.com/ubergarm/l2tp-ipsec-vpn-client
- HA addon/app konfiguráció: https://developers.home-assistant.io/docs/apps/configuration/
- HA repository: https://developers.home-assistant.io/docs/apps/repository/
- HA belső hálózat: https://developers.home-assistant.io/docs/apps/communication/
- strongSwan: https://docs.strongswan.org/docs/latest/config/strongswanConf.html
- IPsec-konfiguráció: https://manpages.debian.org/bookworm/strongswan-starter/ipsec.conf.5.en.html
- PSK-formátum: https://manpages.debian.org/bookworm/strongswan-starter/ipsec.secrets.5.en.html
- PPP: https://docs.kernel.org/networking/ppp_generic.html
- ebusd adaptercím: https://github.com/john30/ebusd/wiki/2.-Run
