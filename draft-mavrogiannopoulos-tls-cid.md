---
title: Datagram Transport Transport Layer Security (DTLS) Transport-Agnostic Security Association Extension
abbrev: DTLS ta_sa Extension
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
  RFC4226:
  RFC5246:
  RFC5705:
  RFC6066:
  RFC6347:
  I-D.ietf-tls-tls13:
  I-D.rescorla-tls-dtls13:

informative:
  I-D.barrett-mobile-dtls:
  RFC4301:
  DTLSMOB:
    title: DTLS Mobility
    author:
      -
        ins: R. Seggelmann
      -
        ins: M. Tuexen
      -
        ins: E.P. Rathgeb
    date: 2012


--- abstract

This memo proposes a new Datagram Transport Transport Layer Security (DTLS) extension that provides the ability to negotiate, during handshake, a transport independent identifier that is unique per security association. This identifier effectively decouples the DTLS session from the underlying transport protocol, allowing the same security association to be migrated across different instances of the same transport, or to a completely different transport.

--- middle

# Introduction

DTLS security context demultiplexing is done via the 5-tuple. Therefore, the security association needs to be re-negotiated from scratch whenever the transport identifiers change. For example, when moving the network attachment from WLAN to a cellular connection, or when the IP address of the IoT devices changes during a sleep cycle. A NAT device may also modify the source UDP port after a short idle period.  In such cases, there is not enough information in the DTLS record header for a server that is handling multiple concurrent sessions to associate the new address to an existing client.

This memo proposes a new TLS extension {{RFC6066}} for DTLS 1.2 and above that provides the ability to negotiate, at handshake time, a transport independent identifier that is unique per security association. We call this identifier Connection ID (CID).  Its function is to effectively decouple the DTLS session from the underlying transport protocol, allowing the same DTLS security association to be migrated across different instances of the same transport, or even to a completely different transport - e.g., from UDP to GSM-SMS as showed in {{fig:transp-handover}}.

~~~~~~~~~~
                                     00
                                     /\
                                     :
 IP                    UDP           : DTLS Record Header
 +-----+-----+-------+ +-----+-----+ : +---------+-------+------
 | src | dst | proto | | src | dst | : | Seq#i   |  CID  | ...
 +-----+-----+-------+ +-----+-----+ : +---------+-------+------
 `----------------+----------------' :              ^
                   `................ : .............'
  <Handover event>                   :
                   GSM-SMS           : DTLS Record Header
                   +-------+-------+ : +---------+-------+-----
                   | tp-oa | tp-da | : | Seq#i+1 |  CID  | ...
                   +-------+-------+ : +---------+-------+-----
                                     :
                                     \/
                                     00
~~~~~~~~~~
{: #fig:transp-handover title="Transparent Handover of DTLS Session"}

We present two methods for producing the CID: the first uses a single value generated unilaterally by the server which is fixed throughout the session, whereas the second provides a sequence of identifiers that are created using a HMAC-based OTP algorithm {{RFC4226}} keyed with a per-session shared secret (see {{sec:ext-cli}} for details). The latter allows a client to shift to a new identifier, for example when switching networks, and is intended as a mechanism to counteract tracking by third party observers.  However, it must be noted that this is not generally applicable as a tracking-protection measure: in fact, it becomes totally ineffective when the client is oblivious of changes in the underlying transport identifiers (e.g., on NAT rebind after timeout), and also does not guarantee unique identifiers (see {{sec:clash}} for further details).  Both methods generate a CID that is 32-bits in size, like the Security Parameter Index (SPI) in IPsec {{RFC4301}}.

Similar approaches to support transparent handover of a DTLS session have been described in {{I-D.barrett-mobile-dtls}} and {{DTLSMOB}}.

# Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}.

# Transport Agnostic Security Associatiation Extension

In order to negotiate a Transport Agnostic Security Association, clients include an extension of type "ta_sa" in the extended client hello ({{sec:ext-cli}}).  Servers that receive an extended hello containing a "ta_sa" extension MAY agree to use a Transport Agnostic Security Association by including an extension of type "ta_sa" in the extended server hello ({{sec:srv-ext}}).

If both server and client agree, the DTLSCiphertext format does change after the DTLS connection state is updated; i.e.: for the sending side, after the ChangeCipherSpec message is sent, for the receiving sides, after the ChangeCipherSpec is received.

The DTLSCiphertext format is changed for both the client and the server.  However, only a client can initiate a switch to an unused 'cid' value; a server MUST utilize the same value seen on the last valid message received by the client.  A server which receives a 'cid' value which is not expected (e.g., a value outside its advertised window) MAY ignore the packet.


~~~~~~~
         struct {
              ContentType type;
              ProtocolVersion version;
              uint16 epoch;
              uint48 sequence_number;
              uint32 cid;                          // New field
              uint16 length;
              select (CipherSpec.cipher_type) {
                case block:  GenericBlockCipher;
                case aead:   GenericAEADCipher;
              } fragment;
         } DTLSCiphertext;
~~~~~~~
{: #fig:record title="Modified DTLS Record Format"}


## Extended Client Hello
{: #sec:ext-cli }

In order to negotiate a Transport Agnostic Security Association, clients include an extension of type "ta_sa" in the extended client hello.  The "extension_data" field of this extension SHALL contain the ClientSecAssocData structure in {{fig:cli-ext}}.

In case the fixed(0) type has been negotiated, the 'cid' of the packets after ChangeCipherSpec is sent explicitly by the server.

In case the hotp(1) type has been negotiated, the initial 'cid' is calculated using the HOTP algorithm ({{RFC4226}}) as follows:

- A 20-byte string is generated using a {{RFC5705}} exporter.  The key material exporter uses the label "EXPORTER-ta-security-association-hotp" without the quotes, and without any context value.
- The initial 'cid' equals to the first HOTP value (i.e., the 31-bit value of Sbits in {{RFC4226}} notation), generated by using the previously exported value as K.

Subsequent values of the HOTP algorithm can be used in place of the initial, as long as they fall into the negotiated window_size (see {{fig:srv-ext}}).

~~~~~~~
         enum {
             fixed(0), hotp(1), (255)
         } SecAssocType;

         struct {
              SecAssocType types<1..2^8-1>;
         } ClientSecAssocData;
~~~~~~~
{: #fig:cli-ext title="ta_sa extension, client"}

## Extended Server Hello
{: #sec:srv-ext }

Servers that receive an extended hello containing a "ta_sa" extension MAY agree to use a Transport Agnostic Security Association by including an extension of type "ta_sa", with "extension_data" being ServerSecAssocData in the extended server hello ({{fig:srv-ext}}).

~~~~~~~
         struct {
              SecAssocType type;
              select (type) {
                  case fixed:
                      struct {
                          uint32 cid_value;
                      };
                  case hotp:
                      struct {
                          uint16 window_size;
                      };
              };
         } ServerSecAssocData;
~~~~~~~
{: #fig:srv-ext title="ta_sa extension, server"}

In case the fixed(0) type is chosen, 'cid_value' contains the value to be used as 'cid'.  In case hotp(1) type is chosen, 'window_size' must be greater or equal to 1, indicating the number of HOTP values that the server can recognize for this particular client.

## Wire Format Changes
{: #sec:new-wire-fmt }
How to signal the modified wire format to the receiving end is currently an open problem.

Note that moving the cid after the length field and computing the difference between the UDP datagram's and DTLS record's lengths is not an option because there is no guarantee that UDP datagrams carry one and one only DTLS record (Section 4.1.1. of {{RFC6347}}).

Ideally, we would just bump the version number, but there seems to be limited room for maneuver given the way TLS encodes version information in the record header, and also given that we want CID to work with DTLS 1.2 and later.

More discussion needed to sort out this point.

# Clashing HOTP CIDs
{: #sec:clash }

HOTP behaves like a PRF, thus uniformly distributing the produced CIDs across the 32-bit space.  {{tab:clash}} presents the probability to end up with two separate sessions having the same HOTP CID when the number of concurrent sessions is increased.

| Sessions | Collision probability                        |
|:---------|:---------------------------------------------|
| 10       |  1.16415320717e-08, or about 1 in 85,899,347 |
| 100      |  1.16415254059e-06, or about 1 in 858,994    |
| 1000     |  0.000116408545826, or about 1 in 8,590      |
| 10000    |  0.011574031737, or about 1 in 86            |
| 100000   |  0.687813095694, or about 1 in 1             |
| 1000000  |  1.0, or about 1 in 1                        |
{: #tab:clash }

The takeaway is that 32-bits are probably too few for highly loaded servers that want to do HOTP as their primary CID allocation strategy.  An alternative would be for the server to stop negotiating 'hotp' and fall back to 'fixed' when the number of active sessions crosses some threshold; another would be to increase the CID space to 40 or 48 bits when HOTP is used.

# Security Considerations

CID does not affect the running protocol in any way other than adding an un-authenticated field to the record header. As such, this identifier has no effect on the overall security of the session with respect to authentication, confidentiality and integrity.  On the other hand, since this identifier is not authenticated, it should not be used in any way that assumes it is, nor be assumed to be secret or unknown to an adversary.  In general, this identifier should not be relied on more than the IP address or UDP port numbers are.

To address the privacy concerns of using a fixed identifier for the lifetime of a session which may roam through multiple networks, we have introduced the hotp identifier type.  This type of identifier gives the client a chance to switch its ts_sa identity when also switching its transport identifiers or network attachment (assuming that client is made aware of the change before it sends a new DTLS record).  The choice of which type of identifier to use is a trade-off between the request for privacy stated by the client and the ability of the server to control the identifiers in use at each point in time, as explained in {{sec:clash}}.

# IANA Considerations

This document adds a new extension for DTLS: ts_sa(TODO).  This extension MUST only be used with DTLS, and not with TLS.  This extension is assigned from the TLS ExtensionType registry defined in {{RFC5246}}.

# Acknowledgments

Thanks to
Achim Kraus,
Carsten Bormann,
Kai Hudalla,
Simon Bernard,
Stephen Farrell,
for helpful comments and discussions that have shaped the document.

This work is partially supported by the European Commission under Horizon 2020 grant agreement no. 688421 Measurement and Architecture for a Middleboxed Internet (MAMI). This support does not imply endorsement.

--- back
