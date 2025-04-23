#!/bin/sh
/Applications/Wireshark.app/Contents/MacOS/Wireshark -o tls.keylog_file:long.keylog -o tls.desegment_ssl_records:TRUE -o tls.desegment_ssl_application_data:TRUE -Y tls -r long.pcap
