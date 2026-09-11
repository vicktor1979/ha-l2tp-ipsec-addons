# Licenc és függőségek

A repository saját vezérlője, TCP-proxyja, Go-illesztője és dokumentációja a gyökérben lévő MIT LICENSE szerint használható.

A Docker-build a **xen0bit/veepin** projekt L2TP API-ját importálja, upstream MIT licenc alatt:

- https://github.com/xen0bit/veepin
- v0.9.6 commit: `6c37e3691c326e54956cea042e2df67d3717e7a4`
- Az upstream LICENSE a kész képben `/usr/share/licenses/veepin/LICENSE` helyre másolódik.

A teljes veepin-forrás nincs beágyazva ebbe a ZIP-be, azt a Docker-build tölti le. A ZIP-ből ezért nem végezhető teljesen offline motor-build.

Az előző 0.1.0 megoldás ötletének kiindulópontja az ubergarm/l2tp-ipsec-vpn-client volt. A 0.2.0 már nem ezt a kliensstack-et futtatja: nincs strongSwan/xl2tpd/pppd a runtime-ban.

A veepin nyilvános L2TP API-ját az átdolgozáskor megvizsgáltuk. A rögzített release-re történő teljes összefordítás ebben a környezetben nem futott le; azt a mellékelt Docker-build/CI ellenőrzi.

A Go, Alpine, Python, iproute2, tini, tzdata és tranzitív Go-modulok saját licencekkel rendelkeznek. Ezeket a terjesztési és csomagmetaadatok szerint kell figyelembe venni. A projekt nem a Home Assistant, Vaillant, Giganet vagy veepin hivatalos terméke, jóváhagyását nem állítjuk.
