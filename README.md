# CIP-B103 Lab [#] – SMTP Email Traffic Forensics: Credential and Message Recovery from a Plaintext Capture

**Student:** Fuseini Imoru Kantuogaa  
**Course:** CIP-B103  
**Lab:** Lab [#] – SMTP Protocol Analysis, Base64 Credential Decoding and Email Content Reconstruction with tshark

## Overview

This lab demonstrates a network-forensics workflow against a captured SMTP session: acquiring and hashing a sample capture, inventorying every SMTP command/response exchanged, reconstructing the TCP stream as a readable conversation, decoding the Base64-encoded AUTH LOGIN username and password, extracting the e-mail's headers and MIME body, mapping the session's network-layer metadata, and confirming whether the session was ever upgraded to TLS. The goal was to show, end-to-end, what an analyst can recover from a single unencrypted SMTP conversation — here, a full set of mail-account credentials and a complete e-mail message in cleartext.

## Case Folder Structure

```
mkdir -p ~/CIP-B103-Lab4/{evidence,working,exported,reports,screenshots,scripts}
cd ~/CIP-B103-Lab4
```

| Folder | Purpose |
|---|---|
| evidence/ | Original downloaded capture, never modified |
| working/ | Working copy of the capture used for all analysis |
| exported/ | Reserved for exported artifacts (unused in this lab) |
| reports/ | All tshark output, hashes, TSVs and extracted stream/text files |
| screenshots/ | Reserved for screen captures |
| scripts/ | Reserved for helper scripts (a short inline Python decoder was used instead, see section 6) |

`pwd` confirmed `/home/kali/CIP-B103-Lab4`; `find . -maxdepth 1 -type d -print` confirmed all seven directories were created.

## 1. Tool Setup

```
sudo apt update
sudo apt install -y wireshark tshark python3
```

wireshark and tshark (4.6.6-1) were already the newest versions. The update pulled 75.9 MB of package lists (1,750 packages upgradable system-wide); the install itself upgraded 8 Python-related packages (python3, python3-dev, python3-minimal, python3-tk, python3-venv, libpython3-dev, libpython3-stdlib, libjs-sphinxdoc) with no new packages installed.

| Tool | Version | Purpose |
|---|---|---|
| tshark / capinfos (Wireshark) | 4.6.6-1 | Capture inspection, protocol decoding, field extraction, TCP stream reassembly |
| python3 | 3.13.9-3+b1 | One-off Base64 decoding of captured credentials |
| wget / sha256sum | Linux | Acquisition and integrity hashing |

## 2. Acquiring the Evidence

```
wget -O evidence/smtp.pcap \
  'https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/smtp.pcap'
```

The request to wiki.wireshark.org redirected (302) to GitLab, which served the file:

| Property | Value |
|---|---|
| Original source | wiki.wireshark.org (Wireshark's official sample-captures wiki page) |
| Resolved source (after redirect) | gitlab.com/wireshark/wireshark/-/wikis/uploads/.../smtp.pcap |
| Downloaded | 2026-08-01 08:42:34–08:42:36 |
| Size | 27,850 bytes (27K) |
| Saved as | evidence/smtp.pcap |

```
cp --preserve=timestamps evidence/smtp.pcap working/smtp_working.pcap
sha256sum evidence/smtp.pcap working/smtp_working.pcap | tee reports/smtp_capture_hashes.txt
```

| File | SHA-256 |
|---|---|
| evidence/smtp.pcap | 17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab |
| working/smtp_working.pcap | 17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab (identical — copy verified) |

```
capinfos evidence/smtp.pcap | tee reports/smtp_capinfos.txt
```

| Field | Value |
|---|---|
| File type | Wireshark/tcpdump – pcap |
| Encapsulation | Ethernet |
| Timestamp precision | microseconds (6) |
| Number of packets | 60 |
| File size / Data size | 27 kB / 26 kB |
| Capture duration | 9.198384 seconds |
| Earliest packet | 2009-10-05 02:06:07.492060 |
| Latest packet | 2009-10-05 02:06:16.690444 |
| Data byte/bit rate | 2,920 bytes/s / 23 kbps |
| Average packet size / rate | 447.77 bytes / 6 packets/s |
| SHA256 / SHA1 (capinfos) | 17ad230db1b6…a47ab / 3def1a1fed849e7f23b66e6925ddff05845a400b |
| Strict time order | True |
| Interfaces | 1 (Ethernet, capture length 65535, 1,000,000 ticks/s, 60 packets) |

## 3. TCP Conversation Overview

```
tshark -r working/smtp_working.pcap -q -z conv,tcp | tee reports/tcp_conversations.txt
```

| Conversation | Duration | Frames A→B | Bytes A→B | Frames B→A | Bytes B→A |
|---|---|---|---|---|---|
| 10.10.1.4:1470 ↔ 74.53.140.153:25 | 7.5777 s | 25 | 1,980 bytes | 28 | 22 kB |

A single TCP session on port 25 (SMTP) between the client (10.10.1.4) and the mail server (74.53.140.153, hostname xc90.websitewelcome.com) accounts for the entire capture.

## 4. Full SMTP Packet Inventory

```
tshark -r working/smtp_working.pcap -Y 'smtp' -T fields \
  -e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e _ws.col.Info \
  | tee reports/smtp_packet_inventory.tsv
wc -l reports/smtp_packet_inventory.tsv | tee reports/smtp_packet_count.txt
```

36 SMTP-tagged lines were produced. Key milestones from the inventory:

| Frame | Time (local) | Direction | Content |
|---|---|---|---|
| 6 | 02:06:08.219663 | S→C | `220-xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500` + anti-spam banner |
| 7 | 02:06:08.224809 | C→S | `EHLO GP` |
| 9 | 02:06:08.566183 | S→C | `250-xc90.websitewelcome.com Hello GP [122.162.143.157] \| SIZE 52428800 \| PIPELINING \| AUTH PLAIN LOGIN \| STARTTLS \| HELP` |
| 10 | 02:06:08.568729 | C→S | `AUTH LOGIN` |
| 11 | 02:06:08.911081 | S→C | `334 VXNlcm5hbWU6` (Base64 prompt for "Username:") |
| 12 | 02:06:08.911655 | C→S | `User: Z3VycGFydGFwQHBhdHJpb3RzLmlu` |
| 13 | 02:06:09.253544 | S→C | `334 UGFzc3dvcmQ6` (Base64 prompt for "Password:") |
| 14 | 02:06:09.254118 | C→S | `Pass: cHVuamFiQDEyMw==` |
| 15 | 02:06:09.613798 | S→C | `235 Authentication succeeded` |
| 16 | 02:06:09.614414 | C→S | `MAIL FROM: <gurpartap@patriots.in>` |
| 17 | 02:06:09.956765 | S→C | `250 OK` |
| 18 | 02:06:09.957250 | C→S | `RCPT TO: <raj_deol2002in@yahoo.co.in>` |
| 19 | 02:06:10.319708 | S→C | `250 Accepted` |
| 20 | 02:06:10.320203 | C→S | `DATA` |
| 21 | 02:06:10.661679 | S→C | `354 Enter message, ending with "." on a line by itself` |
| 22–45 | 02:06:10.69–02:06:11.86 | C→S | Multiple `DATA fragment` / `[TCP Out-Of-Order]` / `[TCP Window Full]` segments (the message body being transmitted) |
| 26, 28–30 | 02:06:10.695 | Router (192.168.1.1) | ICMP "Destination unreachable (Fragmentation needed)" — MTU/PMTU signaling during the large DATA transfer |
| 52 | 02:06:12.248789 | S→C | `250 OK id=1Mugho-0003Dg-Un` (message accepted) |
| 54 | 02:06:14.763825 | C→S | `QUIT` |
| 56 | 02:06:15.105467 | S→C | `221 xc90.websitewelcome.com closing connection` |

## 5. Isolating the SMTP Command/Response Sequence

```
grep -Ei 'HELO|EHLO|MAIL FROM|RCPT TO|DATA|QUIT' reports/smtp_packet_inventory.tsv \
  | tee reports/smtp_command_summary.txt

tshark -r working/smtp_working.pcap -Y 'smtp.req || smtp.rsp' -T fields \
  -e frame.number -e frame.time -e ip.src -e ip.dst \
  -e smtp.req.command -e smtp.req.parameter -e smtp.response.code -e smtp.response \
  | tee reports/smtp_commands_responses.tsv
```

This field-level extraction cleanly separates the protocol's command/parameter and response-code/response-text columns for every SMTP line, confirming the same sequence as the inventory above (EHLO → AUTH LOGIN → two Base64 credential exchanges → 235 success → MAIL FROM → RCPT TO → DATA → 250 accepted → QUIT → 221 closing), and matched identically when re-run with the simpler `-Y smtp` filter.

## 6. Recovering the AUTH LOGIN Credentials (Base64 Decode)

The raw hex/ASCII payload of the two credential frames was pulled first to confirm the exact Base64 strings transmitted:

```
tshark -r working/smtp_working.pcap -Y "frame.number==12 || frame.number==14" -x
```

Frame 12 payload: `Z3VycGFydGFwQHBhdHJpb3RzLmlu` (preceded by `User: `)  
Frame 14 payload: `cHVuamFiQDEyMw==` (preceded by `Pass: `)

These values were then decoded in Python:

```python
import base64

samples = {
    'username': 'Z3VycGFydGFwQHBhdHJpb3RzLmlu',
    'password': 'cHVuamFiQDEyMw==',
}

for label, value in samples.items():
    try:
        decoded = base64.b64decode(value).decode('utf-8', errors='replace')
        print(f'{label}: {decoded}')
    except Exception as exc:
        print(f'{label}: decode failed: {exc}')
```

```
python3 - <<'PYLAB'
...
PYLAB
```

An earlier attempt using placeholder text (`'THE_BASE64_USERNAME_FROM_FRAME_12'`, `'THE_BASE64_PASSWORD_FROM_FRAME_14'`) produced garbled, non-UTF-8 output as expected (`Lq!:◆D◆ ... TN0T@0Mv`), confirming the decoder needed the *actual* captured values rather than placeholders — which were then substituted in:

| Credential | Recovered value |
|---|---|
| **Username** | **gurpartap@patriots.in** |
| **Password** | **punjab@123** |

Because SMTP AUTH LOGIN sends credentials Base64-*encoded*, not encrypted, this is a complete, readable mail-account username and password recovered directly from an unencrypted capture.

## 7. Reconstructing the Full TCP Stream

```
tshark -r working/smtp_working.pcap -Y smtp -T fields -e tcp.stream | sort -u
tshark -r working/smtp_working.pcap -Y "smtp.req.command==AUTH" -T fields -e tcp.stream
tshark -r working/smtp_working.pcap -q -z follow,tcp,ascii,0 | tee reports/smtp_stream_0.txt
```

Only one TCP stream (stream 0) exists in this capture, confirmed both ways. The full ASCII follow-stream reproduces the entire session end-to-end: the Exim banner and anti-spam notice, the full EHLO capability list (`AUTH PLAIN LOGIN`, `STARTTLS`, `HELP`), the AUTH LOGIN exchange (credentials visible as the raw Base64 strings), `MAIL FROM`/`RCPT TO`/`DATA`, the complete e-mail body, and the closing `QUIT`/`221`.

## 8. Extracting E-mail Headers and Body from the Stream

```
grep -Ei '^(Date|From|To|Subject|Message-ID|MIME-Version|Content-Type|User-Agent|X-Mailer):' \
  reports/smtp_stream_0.txt
```

| Header | Value |
|---|---|
| From | "Gurpartap Singh" <gurpartap@patriots.in> |
| To | <raj_deol2002in@yahoo.co.in> |
| Subject | SMTP |
| Date | Mon, 5 Oct 2009 11:36:07 +0530 |
| Message-ID | <000301ca4581$ef9e57f0$cedb07d0$@in> |
| MIME-Version | 1.0 |
| Content-Type | multipart/mixed; (then multipart/alternative; then text/plain; text/html; text/plain) |
| X-Mailer | Microsoft Office Outlook 12.0 |

```
grep -A50 "DATA" reports/smtp_stream_0.txt
```

Following the `354 Enter message...` prompt, the full MIME message was reconstructed, including:

- Multipart boundary structure: `----=_NextPart_000_0004_01CA45B0.095693F0` (mixed), nested `----=_NextPart_001_0005_01CA45B0.095693F0` (alternative)
- A `text/plain; charset=us-ascii` body reading: *"Hello ... I send u smtp pcap file ... Find the attachment ... GPS"*
- A parallel `text/html; charset=us-ascii`, quoted-printable part beginning `<html xmlns:v="urn:schemas-microsoft-com:vml" ...>`
- Outlook-specific anti-spam/puzzle headers (`x-cr-hashedpuzzle`, `x-cr-puzzleid`, `Thread-Index`, `Content-Language: en-us`)

This confirms the e-mail's full plaintext content, sender/recipient and originating mail client (Outlook 12.0, i.e. Outlook 2007) were all recoverable from the capture.

## 9. Network-Layer Metadata

```
tshark -r working/smtp_working.pcap -Y 'smtp' -T fields \
  -e frame.number -e frame.time_epoch -e eth.src -e eth.dst \
  -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.stream \
  | tee reports/smtp_network_metadata.tsv
```

| Role | MAC | IP | Port |
|---|---|---|---|
| Client | 00:1f:33:d9:81:60 | 10.10.1.4 | 1470 |
| Server | 00:e0:1c:3c:17:c2 | 74.53.140.153 | 25 |

This mapping held consistently across every one of the 36 SMTP frames in tcp.stream 0, including the router/next-hop ICMP fragmentation-needed messages from 192.168.1.1 seen earlier during the large DATA transfer (frames 26, 28–30).

## 10. Checking for Client Signatures and TLS Upgrade

```
tshark -r working/smtp_working.pcap \
  -Y 'smtp contains "User-Agent" || smtp contains "X-Mailer"' -T fields \
  -e frame.number -e tcp.stream -e smtp.req.parameter -e data-text-lines \
  | tee reports/client_indicators.tsv
```

| Frame | Finding |
|---|---|
| 22 | Line-based text data (47 lines) — part of the DATA body carrying the X-Mailer header |
| 26 | Line-based text data (12 lines) |

```
tshark -r working/smtp_working.pcap -Y smtp | grep -i STARTTLS
tshark -r working/smtp_working.pcap -Y "smtp.req.command==STARTTLS"
tshark -r working/smtp_working.pcap -Y tls
```

The server's EHLO response (frame 9) advertised `STARTTLS` as a supported capability, but the client never issued a `STARTTLS` command — the `smtp.req.command==STARTTLS` filter and the `tls` display filter both returned **zero matching frames**. The client proceeded directly to `AUTH LOGIN` over the plaintext connection, which is exactly why the credentials in section 6 and the full message in section 8 were recoverable without any decryption step.

## Conclusion

**This capture shows a complete, real-world mail-client session (Outlook 2007) authenticating to an SMTP server and sending an e-mail entirely in the clear.** Although the server offered STARTTLS, the client (EHLO GP) never upgraded the connection, so the AUTH LOGIN exchange — Base64-*encoded*, not encrypted — exposed the account credentials `gurpartap@patriots.in` / `punjab@123` directly in the packet capture, and the subsequent `MAIL FROM`/`RCPT TO`/`DATA` exchange exposed the full e-mail (sender, recipient, subject "SMTP", timestamp, and both the plain-text and HTML bodies reading "I send u smtp pcap file / Find the attachment / GPS") to anyone able to observe the traffic. This is a textbook demonstration of why STARTTLS being merely *offered* by a server is not protection on its own — it must actually be *used* by the client — and why plaintext SMTP AUTH LOGIN should never be treated as a secure authentication mechanism.

## Key Tools Used

| Tool | Purpose |
|---|---|
| wget / sha256sum | Acquiring and hashing the sample capture |
| capinfos | Capture-level metadata and hash verification |
| tshark (-Y, -T fields, -x, -z conv/follow) | SMTP filtering, field extraction, raw hex/ASCII dump, TCP stream reassembly, conversation statistics |
| python3 / base64 | Decoding the captured Base64 username and password |
| grep | Isolating command keywords and e-mail header lines from the reconstructed stream |

## Forensic Notes

- The original `evidence/smtp.pcap` was never modified; all analysis used the `working/` copy, whose SHA-256 (17ad230db1b6…a47ab) matched the evidence file exactly, confirming the copy's integrity.
- This is a well-known, intentionally public Wireshark sample capture (hosted on the Wireshark wiki/GitLab) used for protocol-analysis training; the credentials and e-mail content recovered are from this 2009 sample dataset, not from any live or current system.
- The Base64 decode step was deliberately first run against placeholder strings to confirm the decoder's error-handling behavior (`errors='replace'` producing garbled but non-crashing output) before substituting the real captured values — a sanity check worth noting in the methodology, not an error in the final result.
- `STARTTLS` being advertised in the EHLO response but never invoked by the client is the single most important finding in this lab: it is the reason every subsequent exchange (credentials and e-mail body) was recoverable in plaintext.
- The ICMP "Destination unreachable (Fragmentation needed)" messages from 192.168.1.1 during the DATA transfer (frames 26, 28–30) reflect normal PMTU discovery for the large multipart MIME message and are not evidence of tampering or packet loss attacks.
- Capture timestamps (2009-10-05) predate the Kali host's 2026 system clock seen in command prompts; the 2026 dates reflect only when the lab was performed, not when the traffic was captured.
- All generated reports, hashes and extracted TSV/stream files were written under `reports/`, keeping the original evidence, working copy and derived output cleanly separated for chain of custody.
