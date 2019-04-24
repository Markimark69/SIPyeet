# SIPyeet
[*Discard SIP messages at high velocity.*](https://www.urbandictionary.com/define.php?term=Yeet)

Pst! Hey! You! Yes, you!\
Wanna yeet somewhat RFC compliant SIP messages at unsuspecting SIP UAs?

Then you've come to the right place!

Remember kids: research only!

## Why though? 🤔

Short answer: ¯\\_(ツ)\_/¯

Long answer: While troubleshooting some SIP troubles I found the lack of tools that craft singular SIP messages disturbing.\
 If you need to handle responses (SIP dialogs) and sessions, this isn't the right tool. Check out SIPp and prepare your editor for huge XML docs.

## Installation
### Requirements

The core of this gadget is [scapy](https://scapy.net/). Go get that first.

## Usage

`-src`, `-dst` sets the source / destination address respectively. Scapy will resolve hostnames before putting the Packet on the wire. SIPyeet will not, so hostnames will remain as such in SIP FROM- / TO-fields.\
`-tt` sets the transport mode. If `-tt` is not supplied, SIPyeet defaults to UDP.

## Methods

### OPTIONS
Currently the only implemented SIP Method is OPTIONS.\
Usually used to do weird stuff to physical SIP UAs (i.e. deskphones), like asking them to reboot and reprovision, but it also finds itself being used as a keep-alive method.<sup>Citation needed</sup>
