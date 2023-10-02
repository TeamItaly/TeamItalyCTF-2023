# TeamItaly CTF 2023

## [misc] ZIP Extractor 3000 (3 solves)
A new zip extractor with signature verification.

Site: http://zip-extractor-3000.challs.teamitaly.eu

Author: Giovanni Minotti <@Giotino>

## Challenge

The website allows to to upload a ZIP file and have it extracted. Its content is checked for integrity using a signature that the server can verify, only the provided ZIP should be accepted. Then it checks if the GET_FLAG file contains the correct content and it gives the flag.

## Solution

The user can upload a ZIP file that is read differently by `zipfile` and `7-zip`. The former reads the file from the beginning, while the latter reads it from the end (which is what nearly everyone does). This zip must be the "exploit ZIP" followed by the "provided ZIP". The exploit ZIP should contains the GET_FLAG file with the correct content (described in the challenge source code) and the FILES file with the hash of the GET_FLAG file.