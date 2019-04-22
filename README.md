# SIPyeet

Pst! Hey! You! Yes, you!\
Wanna yeet somewhat RFC compliant SIP messages at unsuspecting SIP UAs?

Then you've come to the right place!

Remember kids, research only!

## Installation
### Requirements

The core of this gadget is [scapy](https://scapy.net/). Go get that first.

## Usage

`-src` sets the source address, Scapy will resolve hostnames before putting the Packet on the wire. SIPyeet will not so hostnames will remain as such in SIP FROM-fields.\
`-dst` sets the destination address and TO-fields.
