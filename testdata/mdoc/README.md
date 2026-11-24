# mdoc test data

The sample DeviceResponse, its document signer certificate, the session
transcript (as SessionTranscriptBytes) and the reader's ephemeral private
key (the P-256 scalar, for the device MAC) from
ISO/IEC 18013-5:2021 Annex D (D.4.1.2), as hex, taken from the
OpenWallet Foundation's multipaz project
(`multipaz/src/commonTest/kotlin/org/multipaz/mdoc/TestVectors.kt`,
Apache License 2.0). The sample's validity ran from 2020-10-01 to
2021-10-01, so tests judge it at a time inside that window.
