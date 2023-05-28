## Synopsis

A ping/traceroute utility written in python. This tool uses ICMP Echo Requests (which requires elevated privileges) and prints round trip time from the response.

The traceroute functionality simply uses the same echo requests but sets the IP TTL starts at 1 which triggers the first router to send a Time Exceeded response (giving us the first hop). The TTL is the incremented by 1 and then another Echo Request is sent to get the next hop. This is repeated up to 64 times or until the destination is reached.

Some really helpful links reguarding ICMP:
https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
http://www.faqs.org/rfcs/rfc1071.html

## Author

Matthew Emerson

## License

Released under MIT License.
