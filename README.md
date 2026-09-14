# Kísérleti Home Assistant L2TP/IPsec C6 átjáró – 0.2.1

Ez a repository a meglévő, PSK + felhasználónév/jelszó alapú L2TP/IPsec
VPN-hez készülő, kísérleti Home Assistant app/addon forrása.
A PPP-t a veepin kezeli felhasználói térben; kernel-PPP nem szükséges.

## A 0.2.1 célja

* `vpn_test`: adaptercím nélkül csak a VPN-kapcsolatot próbálja ki, majd leáll.
* `discover`: sikeres VPN után egyszer átvizsgálja a kifejezetten megadott
  távoli CIDR-eket néhány TCP-porton, és naplózza a válaszokat, majd leáll.
* `proxy`: az eredeti, ismert C6-címhez kötött egyklienses TCP-átjáró.
* `ike_trace`: az addon konténerének külső interfészén az adott VPN-szerverrel
  folytatott IKE-kézfogás fejléc-metaadatait naplózza. Nincs nyers csomagkiírás.

**Az IKE időtúllépésének okát a korábbi napló nem azonosítja. Ez a verzió
nem igazolt kompatibilitási javítás: diagnosztikai és keresési bővítés.
A veepin protokoll- és kriptográfiai megvalósítása változatlan, ugyanabból
az upstream commitból fordul.**

A helyi ellenőrzések a `TEST_REPORT.md` fájlban találhatók. A teljes
Docker-buildet, HA-telepítést és a szolgáltatói VPN-t ehhez a kiadáshoz
nem tudtuk itt kipróbálni. Üzemi rendszer előtt külön teszt szükséges.

## Telepítés és frissítés

A repository teljes tartalmát töltsd fel a saját GitHub-tárolód gyökerébe.
A `repository.yaml` maradjon a gyökérben; a rejtett `.github` mappát is töltsd fel.
Az addon slugja változatlan: `l2tp_ipsec_client`. A saját GitHub-tároló címét
add a Home Assistant alkalmazás-/bővítményáruház tárolóihoz (nem HACS).
Meglévő telepítésnél frissítés után a 0.2.1 verziót ellenőrizd.

Részletek: `UPGRADE.md`, `l2tp_ipsec_client/DOCS.md`, `SECURITY.md`.
Valódi VPN-jelszót, felhasználónevet vagy PSK-t ne tölts fel a GitHubra.

## Rendszer és jogosultságok

A manifest amd64 és aarch64 architektúrát jelöl. Az aarch64 build ebben
az ellenőrzésben nem futott le. TUN, NET_ADMIN és NET_RAW szükséges;
a HA host hálózata, teljes hardverhozzáférés és kernelmodul-betöltés nem.
A gazdarendszer DNS-ét és alapértelmezett útvonalát nem változtatja meg.

## Hivatkozások

* https://developers.home-assistant.io/docs/apps/configuration/
* https://developers.home-assistant.io/docs/apps/repository/
* https://github.com/xen0bit/veepin/blob/main/doc/usage/l2tp.md
* https://www.rfc-editor.org/rfc/rfc3947
* https://adapter.ebusd.eu/v5-c6/steps.en.html

A nyilvános dokumentáció nem garantálja a konkrét VPN-szerverrel való
kompatibilitást. Ez a kliens nem függetlenül auditált megoldás.
