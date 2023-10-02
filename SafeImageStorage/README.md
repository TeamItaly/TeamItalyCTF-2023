# TeamItalyCTF 2023

## [rev] Safe Image Storage (6 solves)
Finally, a place to store your images securely encrypted.

Site: http://safeimagestorage.challs.teamitaly.eu

Author: Gianluca Altomani <@devgianlu>

## Solution

The website allows you to request encrypted images via a custom protocol. The encryption is performed with a server key
and a client key, the server encrypts using a combination of both keys and returns the encrypted data which is then
decrypted by the browser for displaying. Knowing the server key makes it possible to view all images.

The request is composed as follows (all big endian):

- 4 bytes of magic: `devg`
- 1 byte of options
- 16 bytes client key
- 2 bytes filename length
- Filename
- 4 bytes of crc32

The trick is in the options byte: the default cipher used is AES-CBC (0), but it can be changed to AES-CTR (1),
AES-CFB (2) or AES-ECB (3). Since only the pixels part of the image is ciphered (not the metadata), it is possible to
read the flag ciphered with AES-ECB.