# ssdp

Stupid Simple Dumps Parser for binary dumps?
- just for mifare 1k/4k dumps

## usage

- the tools parse the content as N-bytes word (N = 2, 4, 8). N can be specified with `--units N`
- it shows the block and units that are different across dumps
- a couple of different visualization/encoding strategies are used for easier reverse engineering (`NOT = bitwise not, LE = little endian, BE = big endiand`)

From the above
- identify which blocks hold relevant information
- duplicate one dump
- modify the content with the new data

Let's take an hypothetical scenario in which we have two dumps for a mifare card obtained using a proxmark3. `dump2` was obtained right after adding `2` units of credits to the tag.
- `dump1` with `1.5` unit of credits
- `dump2` with `3.5` unit of credits

```
> ./main.py --units 4 --format mf1k --show NOT_RAW,INT_LE,NOT_LE --colorize INT_LE,NOT_LE \
    data/dump1.bin data/dump2.bin

Inputs:
  data01: data/dump1.bin
  data02: data/dump2.bin

Diff blocks:
  S=1 B=2 (abs=6)
  S=2 B=0 (abs=8)
  S=2 B=1 (abs=9)

[BLOCK] S=1 B=2 (abs=6)
  [units=4]
    data01: FULL=39 4A E2 32 | 00 00 00 00 | 00 00 00 00 | C3 01 00 07
    data02: FULL=70 4A E2 32 | 00 00 00 00 | 00 00 00 00 | C4 01 00 15
    +00
      data01: RAW=39 4A E2 32 | NOT_RAW=C6 B5 1D CD | INT_LE= 853690937 | NOT_LE=3441276358
      data02: RAW=70 4A E2 32 | NOT_RAW=8F B5 1D CD | INT_LE= 853690992 | NOT_LE=3441276303
    +12
      data01: RAW=C3 01 00 07 | NOT_RAW=3C FE FF F8 | INT_LE= 117440963 | NOT_LE=4177526332
      data02: RAW=C4 01 00 15 | NOT_RAW=3B FE FF EA | INT_LE= 352321988 | NOT_LE=3942645307

[BLOCK] S=2 B=0 (abs=8)
  [units=4]
    data01: FULL=96 00 00 00 | 69 FF FF FF | 96 00 00 00 | 09 F6 09 F6
    data02: FULL=5E 01 00 00 | A1 FE FF FF | 5E 01 00 00 | 09 F6 09 F6
    +00
      data01: RAW=96 00 00 00 | NOT_RAW=69 FF FF FF | INT_LE=       150 | NOT_LE=4294967145
      data02: RAW=5E 01 00 00 | NOT_RAW=A1 FE FF FF | INT_LE=       350 | NOT_LE=4294966945
    +04
      data01: RAW=69 FF FF FF | NOT_RAW=96 00 00 00 | INT_LE=4294967145 | NOT_LE=       150
      data02: RAW=A1 FE FF FF | NOT_RAW=5E 01 00 00 | INT_LE=4294966945 | NOT_LE=       350
    +08
      data01: RAW=96 00 00 00 | NOT_RAW=69 FF FF FF | INT_LE=       150 | NOT_LE=4294967145
      data02: RAW=5E 01 00 00 | NOT_RAW=A1 FE FF FF | INT_LE=       350 | NOT_LE=4294966945

[BLOCK] S=2 B=1 (abs=9)
  [units=4]
    data01: FULL=32 00 00 00 | CD FF FF FF | 32 00 00 00 | 09 F6 09 F6
    data02: FULL=96 00 00 00 | 69 FF FF FF | 96 00 00 00 | 09 F6 09 F6
    +00
      data01: RAW=32 00 00 00 | NOT_RAW=CD FF FF FF | INT_LE=        50 | NOT_LE=4294967245
      data02: RAW=96 00 00 00 | NOT_RAW=69 FF FF FF | INT_LE=       150 | NOT_LE=4294967145
    +04
      data01: RAW=CD FF FF FF | NOT_RAW=32 00 00 00 | INT_LE=4294967245 | NOT_LE=        50
      data02: RAW=69 FF FF FF | NOT_RAW=96 00 00 00 | INT_LE=4294967145 | NOT_LE=       150
    +08
      data01: RAW=32 00 00 00 | NOT_RAW=CD FF FF FF | INT_LE=        50 | NOT_LE=4294967245
      data02: RAW=96 00 00 00 | NOT_RAW=69 FF FF FF | INT_LE=       150 | NOT_LE=4294967145
```

From the output and what it's known about the credit on the tag, it's clear that

- `S1B2`: holds information that is not trivially related to the data

- `S2B0` (`block8`):
    - bytes `S2B0+00-04` contains the current credit in cents (`150` -> `1.5` for dump1, `350` -> `3.5` for dump2)
    - bytes `S2B0+04-08` contains the current credit in cents (`150` -> `1.5` for dump1, `350` -> `3.5` for dump2) in bitwise not representation
    - bytes `S2B0+08-12` contains the current credit in cents (`150` -> `1.5` for dump1, `350` -> `3.5` for dump2)

- `S2B1` (`block9`):
    - bytes `S2B1+00-04` contains the previous credit in cents (`50` -> `0.5` for dump1, `150` -> `1.5` for dump2)
    - bytes `S2B1+04-08` contains the previous credit in cents (`50` -> `0.5` for dump1, `150` -> `1.5` for dump2) in bitwise not representation
    - bytes `S2B1+08-12` contains the previous credit in cents (`50` -> `0.5` for dump1, `150` -> `1.5` for dump2)


So, if one would want to write a new credit on the card, let's say `69.42` as a `4` bytes word, they would need to recover the byte representation of `6942` in `INT_LE` and `NOT_LE`, as follow

```
> ./conv.py 6942 4
INT_BE : 00001b1e
INT_LE : 1e1b0000
NOT_BE : ffffe4e1
NOT_LE : e1e4ffff
NOT_RAW: ffff96bd
RAW    : 00006942
```

and then write the block using proxmark pm3 `.. wrbl --blk BLOCKN -d [INT_LE][NOT_LE][INT_LE][FIXED_DATA] -k KEY`

```
[usb] pm3 --> hf mf wrbl --blk 8 -d 1e1b0000e1e4ffff1e1b000009f609f6 -k FFFFFFFFFFFF
[usb] pm3 --> hf mf wrbl --blk 9 -d 1e1b0000e1e4ffff1e1b000009f609f6 -k FFFFFFFFFFFF
```

this will set the current and previous credit to `69.42`
