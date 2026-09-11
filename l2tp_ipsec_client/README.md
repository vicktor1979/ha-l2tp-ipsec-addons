# L2TP/IPsec Client – C6 átjáró 0.2.0

Kísérleti, kernel-PPP nélküli Home Assistant-addon távoli eBUS C6 adapterhez.

A régi `CONFIG_PPP=n` problémát userspace VPN-motorral kerüli meg. TUN-t használ, a VPN és az adapter /32 útvonala a saját konténerben marad. Nem általános VPN-útválasztó az összes HA-alkalmazás számára.

Első indítás: **`diagnostics_only: true`**, VPN-titkok nélkül, Védett móddal. A teljes telepítési és használati leírás a **Dokumentáció** lapon, illetve a [DOCS.md](DOCS.md) fájlban.

A teljes Docker-build, HA OS-telepítés és valódi Giganet VPN-kapcsolat nincs még igazolva. Csak kísérleti teszteléshez. Az `amd64` és `aarch64` szerepel a manifestben; 32 bites ARM nem.
