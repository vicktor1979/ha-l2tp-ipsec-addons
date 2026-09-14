# L2TP/IPsec Client – C6 átjáró 0.2.1

Kísérleti userspace PPP/IPsec motor, TUN alapú működés. Három választható mód:
`vpn_test`, `discover`, `proxy`. Adaptercím nélkül is kipróbálható a VPN,
a megadott távoli CIDR-ekben pedig egyszeri TCP-eszközkeresés végezhető.
Az IKE-kézfogás metaadat-naplózása külön bekapcsolható.

Nem igazolt javítás a szolgáltatói IKE időtúllépésre, és nem általános
VPN-átjáró a teljes Home Assistantnak. A kriptográfiai motor változatlan.
Kövesd a DOCS.md, illetve a repository UPGRADE.md és SECURITY.md leírását.
