# 0.2.1 – 2026-09-14

* Adapter-IP nélkül használható egyszeri `vpn_test` mód.
* Külön `discover` mód: sikeres VPN után explicit távoli CIDR-ekben
  korlátozott TCP connect/close keresés; logolt találatok; nincs auto-kiválasztás.
* IKEv1 fejléc-metaadatok opcionális, helyi konténeren belüli naplózása.
* A kétszer kiírt motorhiba egyik példánya eltávolítva.
* Proxy esetén marad a /32 útvonal; a keresés csak a megadott célhálózatokra irányít.
* A VPN-motor upstream commitja és kriptográfiai/protokollkódja változatlan.
  Ez nem igazolt javítás a Giganet IKE-időtúllépésére.

# 0.2.0 – 2026-09-11 – KÍSÉRLETI

- strongSwan/xl2tpd/pppd helyett veepin L2TP/IPsec könyvtár + kisméretű Go-illesztő.
- Nincs `/dev/ppp`, kernel-PPP, kernel-L2TP vagy XFRM-követelmény; TUN továbbra is kell.
- Új TUN-/motor-diagnosztika; a régi félrevezető `/dev/ppp` hiba megszűnik a forrásból.
- Nincs teljes hardverhozzáférés és kernelmodul-betöltés; AppArmor visszakapcsolva.
- A C6 TCP-kapcsolata a VPN-interfészhez és forráscímhez kötött, adapter /32 útvonallal.
- A HA-gazdarendszer hálózata/DNS-e változatlan; alapból nincs LAN-portközzététel.
- Privát pipe-on átadott titkok, naplómaszkolás, behatárolt újrapróbálkozás, egy aktív C6-kliens.
- `amd64` mellett `aarch64` manifestengedély. A teljes build/futtatás még nincs igazolva egyik architektúrán sem.
- 42 Python-teszt, 2 önálló Go-bemenetellenőrzési teszt; valódi VPN- és HA OS-teszt még nincs.

**Kompatibilitási változás:** `ppp_auth` csak `mschapv2`, `legacy_compatibility` csak `false`. Az új motor algoritmusait a régi kapcsoló nem módosítja. Frissítés előtt olvasd el a DOCS.md és a gyökérszintű UPGRADE.md fájlt.

# 0.1.0 – korábbi prototípus

amd64, strongSwan + xl2tpd + pppd; kernel-PPP-támogatást igényelt. A felhasználó HA OS-én `CONFIG_PPP=n`, ezért ott ez az adatút nem használható. A jogosultsági hibaszöveg nem különböztette meg megfelelően a hiányzó kernel-támogatást.
