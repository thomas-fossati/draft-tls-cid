---
title: Transport Agnostic Security Association Extension for TLS
abbrev: TLS CID Extension
docname: draft-mavrogiannopoulos-tls-cid-latest
category: std

ipr: trust200902
area: Security
workgroup: TLS Working Group
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: o-*+
  compact: yes
  subcompact: yes

author:
 -
    ins: N. Mavrogiannopoulos
    name: Nikos Mavrogiannopoulos
    organization: RedHat
    email: nmav@redhat.com
 -
    ins: H. Tschofenig
    name: Hannes Tschofenig
    organization: ARM
    email: hannes.tschofenig@arm.com
 -
    ins: T. Fossati
    name: Thomas Fossati
    organization: Nokia
    email: thomas.fossati@nokia.com

normative:
  RFC2119:
  RFC5246:
  RFC6347:
  I-D.ietf-tls-tls13:
  draft-rescorla-tls-dtls13:
  RFC6066:

informative:
  I-D.barrett-mobile-dtls:

--- abstract

TODO

--- middle

# Introduction

In DTLS, security context demultiplexing is done via the 5-tuple. This implies that the associated DTLS context needs to be re-negotiated from scratch whenever the transport identifiers change. For example, when moving the network attachment from WLAN to a cellular connection, or when the IP address of the IoT devices changes during a sleep cycle. A NAT device may also modify the source UDP port after an idle period.  In such situations, there is not enough information in the DTLS record header for a DTLS server, which handles multiple clients, to associate the new address to an existing client.

This memo proposes a new TLS extension {{RFC6066}} that allows a transport independent identifier to be associated to a given DTLS session.

# Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}.

# A Section


~~~~~~~~~~
  A picture  
~~~~~~~~~~
{: #figxxx title="xxx"}


# Security Considerations

TODO

# IANA Considerations

TODO

# Acknowledgments

TODO

--- back
