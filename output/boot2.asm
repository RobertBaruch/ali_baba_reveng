    PROCESSOR 6502

    MACRO STOW
        LDA      #<{1}
        STA      {2}
        LDA      #>{1}
        STA      {2}+1
    ENDM
    MACRO STOW2
        LDA      #>{1}
        STA      {2}+1
        LDA      #<{1}
        STA      {2}
    ENDM
    MACRO MOVB
        LDA    {1}
        STA    {2}
    ENDM
    MACRO STOB
        LDA    {1}
        STA    {2}
    ENDM
    MACRO MOVW
        LDA    {1}
        STA    {2}
        LDA    {1}+1
        STA    {2}+1
    ENDM
    MACRO PSHW
        LDA    {1}
        PHA
        LDA    {1}+1
        PHA
    ENDM
    MACRO PULB
        PLA
        STA    {1}
    ENDM
    MACRO PULW
        PLA
        STA    {1}+1
        PLA
        STA    {1}
    ENDM
    MACRO INCW
        INC    {1}
        BNE    .continue
        INC    {1}+1
.continue
    ENDM
    MACRO ADDA
        CLC
        ADC    {1}
        STA    {1}
        BCC    .continue
        INC    {1}+1
.continue
    ENDM
    MACRO ADDAC
        ADC    {1}
        STA    {1}
        BCC    .continue
        INC    {1}+1
.continue
    ENDM
    MACRO ADDB
        LDA    {1}
        CLC
        ADC    {2}
        STA    {1}
        BCC    .continue
        INC    {1}+1
.continue
    ENDM
    MACRO ADDB2
        CLC
        LDA    {1}
        ADC    {2}
        STA    {1}
        BCC    .continue
        INC    {1}+1
.continue
    ENDM
    MACRO ADDW
        CLC
        LDA    {1}
        ADC    {2}
        STA    {3}
        LDA    {1}+1
        ADC    {2}+1
        STA    {3}+1
    ENDM
    MACRO ADDWC
        LDA    {1}
        ADC    {2}
        STA    {3}
        LDA    {1}+1
        ADC    {2}+1
        STA    {3}+1
    ENDM
    MACRO SUBB
        LDA    {1}
        SEC
        SBC    {2}
        STA    {1}
        BCS    .continue
        DEC    {1}+1
.continue
    ENDM
    MACRO SUBB2
        SEC
        LDA    {1}
        SBC    {2}
        STA    {1}
        BCS    .continue
        DEC    {1}+1
.continue
    ENDM
    MACRO SUBW
        SEC
        LDA    {1}
        SBC    {2}
        STA    {3}
        LDA    {1}+1
        SBC    {2}+1
        STA    {3}+1
    ENDM
    MACRO SUBWL
        SEC
        LDA    <{1}
        SBC    {2}
        STA    {3}
        LDA    >{1}
        SBC    {2}+1
        STA    {3}+1
    ENDM
    MACRO ROLW
        ROL    {1}
        ROL    {1}+1
    ENDM
    MACRO RORW
        ROR    {1}+1
        ROR    {1}
    ENDM
WNDLFT      EQU     $20
WNDWDTH     EQU     $21
WNDTOP      EQU     $22
WNDBTM      EQU     $23
CH          EQU     $24
CV          EQU     $25
IWMDATAPTR  EQU     $26     ; IWM pointer to write disk data to
IWMSLTNDX   EQU     $2B     ; IWM Slot times 16
INVFLG      EQU     $32
PROMPT      EQU     $33
CSW         EQU     $36     ; 2 bytes

; Details https://6502disassembly.com/a2-rom/APPLE2.ROM.html
IWMSECTOR   EQU     $3D  ; IWM sector to read
RDSECT_PTR  EQU     $3E  ; 2 bytes
RANDOM_VAL  EQU     $4E  ; 2 bytes

INIT        EQU     $FB2F
VTAB        EQU     $FC22
HOME        EQU     $FC58
CLREOL      EQU     $FC9C
RDKEY       EQU     $FD0C
GETLN1      EQU     $FD6F
COUT        EQU     $FDED
COUT1       EQU     $FDF0
SETVID      EQU     $FE93
SETKBD      EQU     $FE89
PHASEOFF        EQU     $C080
PHASEON         EQU     $C081
MOTOROFF        EQU     $C088
MOTORON         EQU     $C089
DRV0EN          EQU     $C08A
DRV1EN          EQU     $C08B
Q6L             EQU     $C08C
Q6H             EQU     $C08D
Q7L             EQU     $C08E
Q7H             EQU     $C08F

CURR_TRACK      EQU     $0478
TRACK_FOR_DRIVE_1 EQU   $0478   ; reused
RESEEKCNT       EQU     $04F8
TRACK_FOR_DRIVE_2 EQU   $04F8   ; reused
READ_CTR        EQU     $0578
SLOTPG5         EQU     $05F8
SLOTPG6         EQU     $0678
RECALIBCNT      EQU     $06F8

RWTS_SCRATCH    EQU     $26
RWTS_SCRATCH2   EQU     $27
DEST_TRACK      EQU     $2A
SLOT16          EQU     $2B
CKSUM_ON_DISK   EQU     $2C
SECTOR_DSK      EQU     $2D
TRACK_ON_DISK   EQU     $2E
VOLUME_ON_DISK  EQU     $2F
CHECKSUM_DISK   EQU     $2F     ; reused
ZPAGE_DRIVE     EQU     $35
PTR2DCT         EQU     $3C     ; 2 bytes
PTR2BUF         EQU     $3E     ; 2 bytes
FORMAT_SECTOR   EQU     $3F     ; reused
FORMAT_VOLUME   EQU     $41
FORMAT_TRACK    EQU     $44
SYNC_CTR        EQU     $45
MOTOR_TIME      EQU     $46     ; 2 bytes
PTR2IOB         EQU     $48     ; 2 bytes
DEBUG_JUMP      EQU     $7C
SECTORS_PER_TRACK EQU   $7F

main    EQU     $0800

    ORG         $2300

boot2:
    SUBROUTINE

    LDA      #$1F
    STA      $7B

.loop:
    LDA      #>boot2_iob            ; call RWTS with IOB
    LDY      #<boot2_iob
    JSR      RWTS_entry
    BCS      .loop                  ; on error, try again

    INC      sector_count
    LDA      sector_count
    CMP      #26
    BEQ      .start_main            ; done loading 26 sectors?

    INC      boot2_iob.buffer+1     ; increment page
    INC      boot2_iob.sector       ; increment sector and track
    LDA      boot2_iob.sector
    CMP      #16
    BNE      .loop

    LDA      #$00
    STA      boot2_iob.sector
    INC      boot2_iob.track
    JMP      .loop
.start_main:
    STOB     #$60, DEBUG_JUMP       ; an RTS instruction
    STOB     #16, SECTORS_PER_TRACK
    JSR      INIT
    JSR      SETVID
    JSR      SETKBD
    JMP      main

sector_count:
    HEX      00
BACK_TO_BOOT2:
    HEX      00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
boot2_iob:
    HEX      01         ; table type, must be 1
    HEX      60         ; slot times 16
    HEX      01         ; drive number
    HEX      00         ; volume number
boot2_iob.track:
    HEX      01         ; track number
boot2_iob.sector:
    HEX      00         ; sector number
boot2_iob.dct_addr:
    WORD     boot2_dct  ; address of device characteristics table
boot2_iob.buffer:
    WORD     #$0800     ; address of buffer
    HEX      00 00
boot2_iob.command:
    HEX      01         ; command byte (read)
    HEX      00         ; return code
    HEX      00         ; last volume number
    HEX      60         ; last slot times 16
    HEX      01         ; last drive number
boot2_dct:
    HEX      00        ; device type, must be 0
    HEX      01        ; phases per track, must be 1
    WORD     #$D8EF    ; motor on time count
    HEX      00 00 00
    HEX      00 00 00 00 00 00 DE 00
    HEX      00 00 02 00 01 01 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
    HEX      00 00 00 00 00 00 00 00
PRENIBBLE:
    ; Converts 256 bytes of data to 342 6-bit nibbles.
    SUBROUTINE

    LDX      #$00
    LDY      #$02

.loop1:
    DEY
    LDA      (PTR2BUF),Y
    LSR
    ROL      SECONDARY_BUFF,X
    LSR
    ROL      SECONDARY_BUFF,X
    STA      PRIMARY_BUFF,Y
    INX
    CPX      #$56
    BCC      .loop1
    LDX      #$00
    TYA
    BNE      .loop1
    LDX      #$55

.loop2:
    LDA      SECONDARY_BUFF,X
    AND      #$3F
    STA      SECONDARY_BUFF,X
    DEX
    BPL      .loop2
    RTS
WRITE:
    ; Writes a sector to disk.
    SUBROUTINE

    SEC
    STX      RWTS_SCRATCH2
    STX      SLOTPG6
    LDA      Q6H,X
    LDA      Q7L,X
    BMI      .protected
    LDA      SECONDARY_BUFF
    STA      RWTS_SCRATCH
    LDA      #$FF
    STA      Q7H,X
    ORA      Q6L,X
    PHA
    PLA
    NOP
    LDY      #$04

.write_4_ff:
    PHA
    PLA
    JSR      WRITE2
    DEY
    BNE      .write_4_ff

    LDA      #$D5
    JSR      WRITE1
    LDA      #$AA
    JSR      WRITE1
    LDA      #$AD
    JSR      WRITE1
    TYA
    LDY      #$56
    BNE      .do_eor

.get_nibble:
    LDA      SECONDARY_BUFF,Y

.do_eor:
    EOR      SECONDARY_BUFF-1,Y
    TAX
    LDA      WRITE_XLAT_TABLE,X
    LDX      RWTS_SCRATCH2
    STA      Q6H,X
    LDA      Q6L,X
    DEY
    BNE      .get_nibble

    LDA      RWTS_SCRATCH
    NOP

.second_eor:
    EOR      PRIMARY_BUFF,Y
    TAX
    LDA      WRITE_XLAT_TABLE,X
    LDX      SLOTPG6
    STA      Q6H,X
    LDA      Q6L,X
    LDA      PRIMARY_BUFF,Y
    INY
    BNE      .second_eor

    TAX
    LDA      WRITE_XLAT_TABLE,X
    LDX      RWTS_SCRATCH2
    JSR      WRITE3
    LDA      #$DE
    JSR      WRITE1
    LDA      #$AA
    JSR      WRITE1
    LDA      #$EB
    JSR      WRITE1
    LDA      #$FF
    JSR      WRITE1
    LDA      Q7L,X

.protected:
    LDA      Q6L,X
    RTS
WRITE1:
    SUBROUTINE

    CLC

WRITE2:
    SUBROUTINE

    PHA
    PLA

WRITE3:
    SUBROUTINE

    STA      Q6H,X
    ORA      Q6L,X
    RTS
POSTNIBBLE:
    ; Converts nibbled data to regular data in PTR2BUF.
    SUBROUTINE

    LDY      #$00

.loop:
    LDX      #$56

.loop2:
    DEX
    BMI      .loop
    LDA      PRIMARY_BUFF,Y
    LSR      SECONDARY_BUFF,X
    ROL
    LSR      SECONDARY_BUFF,X
    ROL
    STA      (PTR2BUF),Y
    INY
    CPY      RWTS_SCRATCH
    BNE      .loop2
    RTS
READ:
    ; Reads a sector from disk.
    SUBROUTINE

    LDY      #$20

.await_prologue:
    DEY
    BEQ      read_error

.await_prologue_d5:
    LDA      Q6L,X
    BPL      .await_prologue_d5

.check_for_d5:
    EOR      #$D5
    BNE      .await_prologue
    NOP

.await_prologue_aa:
    LDA      Q6L,X
    BPL      .await_prologue_aa
    CMP      #$AA
    BNE      .check_for_d5
    LDY      #$56

.await_prologue_ad:
    LDA      Q6L,X
    BPL      .await_prologue_ad
    CMP      #$AD
    BNE      .check_for_d5
    LDA      #$00

.loop:
    DEY
    STY      RWTS_SCRATCH

.await_byte1:
    LDY      Q6L,X
    BPL      .await_byte1
    EOR      ARM_MOVE_DELAY,Y
    LDY      RWTS_SCRATCH
    STA      SECONDARY_BUFF,Y
    BNE      .loop

.save_index:
    STY      RWTS_SCRATCH

.await_byte2:
    LDY      Q6L,X
    BPL      .await_byte2
    EOR      ARM_MOVE_DELAY,Y
    LDY      RWTS_SCRATCH
    STA      PRIMARY_BUFF,Y
    INY
    BNE      .save_index

.read_checksum:
    LDY      Q6L,X
    BPL      .read_checksum
    CMP      ARM_MOVE_DELAY,Y
    BNE      read_error

.await_epilogue_de:
    LDA      Q6L,X
    BPL      .await_epilogue_de
    CMP      #$DE
    BNE      read_error
    NOP

.await_epilogue_aa:
    LDA      Q6L,X
    BPL      .await_epilogue_aa
    CMP      #$AA
    BEQ      good_read

read_error:
    SEC
    RTS
READ_ADDR:
    ; Reads an address header from disk.
    SUBROUTINE

    LDY      #$FC
    STY      RWTS_SCRATCH

.await_prologue:
    INY
    BNE      .await_prologue_d5
    INC      RWTS_SCRATCH
    BEQ      read_error

.await_prologue_d5:
    LDA      Q6L,X
    BPL      .await_prologue_d5

.check_for_d5:
    CMP      #$D5
    BNE      .await_prologue
    NOP

.await_prologue_aa:
    LDA      Q6L,X
    BPL      .await_prologue_aa
    CMP      #$AA
    BNE      .check_for_d5
    LDY      #$03

.await_prologue_96:
    LDA      Q6L,X
    BPL      .await_prologue_96
    CMP      #$96
    BNE      .check_for_d5
    LDA      #$00

.calc_checksum:
    STA      RWTS_SCRATCH2

.get_header:
    LDA      Q6L,X
    BPL      .get_header
    ROL
    STA      RWTS_SCRATCH

.read_header:
    LDA      Q6L,X
    BPL      .read_header
    AND      RWTS_SCRATCH
    STA      CKSUM_ON_DISK,Y
    EOR      RWTS_SCRATCH2
    DEY
    BPL      .calc_checksum
    TAY
    BNE      read_error

.await_epilogue_de:
    LDA      Q6L,X
    BPL      .await_epilogue_de
    CMP      #$DE
    BNE      read_error
    NOP

.await_epilogue_aa:
    LDA      Q6L,X
    BPL      .await_epilogue_aa
    CMP      #$AA
    BNE      read_error

good_read:
    CLC
    RTS
SEEKABS:
    ; Moves disk arm to a given half-track.
    SUBROUTINE

    STX      SLOT16
    STA      DEST_TRACK
    CMP      CURR_TRACK
    BEQ      entry_off_end
    LDA      #$00
    STA      RWTS_SCRATCH

.save_curr_track:
    LDA      CURR_TRACK
    STA      RWTS_SCRATCH2
    SEC
    SBC      DEST_TRACK
    BEQ      .at_destination
    BCS      .move_down
    EOR      #$FF
    INC      CURR_TRACK
    BCC      .check_delay_index

.move_down:
    ADC      #$FE
    DEC      CURR_TRACK

.check_delay_index:
    CMP      RWTS_SCRATCH
    BCC      .check_within_steps
    LDA      RWTS_SCRATCH

.check_within_steps:
    CMP      #$0C
    BCS      .turn_on
    TAY

.turn_on:
    SEC
    JSR      ON_OR_OFF
    LDA      ON_TABLE,Y
    JSR      ARM_MOVE_DELAY
    LDA      RWTS_SCRATCH2
    CLC
    JSR      ENTRY_OFF
    LDA      OFF_TABLE,Y
    JSR      ARM_MOVE_DELAY
    INC      RWTS_SCRATCH
    BNE      .save_curr_track

.at_destination:
    JSR      ARM_MOVE_DELAY
    CLC

ON_OR_OFF:
    LDA      CURR_TRACK

ENTRY_OFF:
    AND      #$03
    ROL
    ORA      SLOT16
    TAX
    LDA      PHASEOFF,X
    LDX      SLOT16

entry_off_end:
    RTS

garbage:
    HEX      AA A0 A0
ARM_MOVE_DELAY:
    ; Delays during arm movement.
    SUBROUTINE

    LDX      #$11

.delay1:
    DEX
    BNE      .delay1
    INC      MOTOR_TIME
    BNE      .delay2
    INC      MOTOR_TIME+1

.delay2:
    SEC
    SBC      #$01
    BNE      ARM_MOVE_DELAY
    RTS
ON_TABLE:
    HEX      01 30 28 24 20 1E 1D 1C 1C 1C 1C 1C

OFF_TABLE:
    HEX      70 2C 26 22 1F 1E 1D 1C 1C 1C 1C 1C
WRITE_XLAT_TABLE:
    HEX      96 97 9A 9B 9D 9E 9F A6 A7 AB AC AD AE AF B2 B3
    HEX      B4 B5 B6 B7 B9 BA BB BC BD BE BF CB CD CE CF D3
    HEX      D6 D7 D9 DA DB DC DD DE DF E5 E6 E7 E9 EA EB EC
    HEX      ED EE EF F2 F3 F4 F5 F6 F7 F9 FA FB FC FD FE FF
    HEX      B3 B3 A0 E0 B3 C3 C5 B3 A0 E0 B3 C3 C5 B3 A0 E0
    HEX      B3 B3 C5 AA A0 82 B3 B3 C5 AA A0 82 C5 B3 B3 AA
    HEX      88 82 C5 B3 B3 AA 88 82 C5 C4 B3 B0 88
READ_XLAT_TABLE:
    HEX      00 01 98 99 02 03 9C 04 05 06 A0 A1 A2 A3 A4 A5
    HEX      07 08 A8 A9 AA 09 0A 0B 0C 0D B0 B1 0E 0F 10 11
    HEX      12 13 B8 14 15 16 17 18 19 1A C0 C1 C2 C3 C4 C5
    HEX      C6 C7 C8 C9 CA 1B CC 1C 1D 1E D0 D1 D2 1F D4 D5
    HEX      20 21 D8 22 23 24 25 26 27 28 E0 E1 E2 E3 E4 29
    HEX      2A 2B E8 2C 2D 2E 2F 30 31 32 F0 F1 33 34 35 36
    HEX      37 38 F8 39 3A 3B 3C 3D 3E 3F
PRIMARY_BUFF:
    ; Initially contains this garbage.
    HEX      00 38 11 0A 08 20 20 0E 18 06 02 31 02 09 08 27
    HEX      22 00 12 0A 0A 04 00 00 03 2A 00 04 00 00 22 08
    HEX      10 28 12 02 00 02 08 11 0A 08 02 28 11 01 39 22
    HEX      31 01 05 18 20 28 02 10 06 02 09 02 05 2C 10 00
    HEX      08 2E 00 05 02 28 18 02 30 23 02 20 32 04 11 02
    HEX      14 02 08 09 12 20 0E 2F 23 30 2F 23 30 0C 17 2A
    HEX      3F 27 23 30 37 23 30 12 1A 08 30 0F 08 30 0F 27
    HEX      23 30 37 23 30 3A 22 34 3C 2A 35 08 35 0F 2A 2A
    HEX      08 35 0F 2A 25 08 35 0F 29 10 08 31 0F 29 11 08
    HEX      31 0F 29 0F 08 31 0F 29 10 11 11 11 0F 12 12 01
    HEX      0F 27 23 30 2F 23 30 1A 02 2A 08 35 0F 2A 37 08
    HEX      35 0F 2A 2A 08 35 0F 2A 3A 08 35 0F 06 2F 23 30
    HEX      2F 23 30 18 12 12 01 0F 27 23 30 37 23 30 1A 3A
    HEX      3A 3A 02 2A 3A 3A 12 1A 27 23 30 37 23 30 18 22
    HEX      29 3A 24 28 25 22 25 3A 24 28 25 22 25 24 24 32
    HEX      25 34 25 24 24 32 25 34 25 24 28 32 28 29 21 29
SECONDARY_BUFF:
    ; Initially contains this garbage.
    HEX      00 E1 45 28 21 82 80 38 62 19 0B C5 0B 24 21 9C
    HEX      88 00 48 28 2B 10 00 03 0C A9 01 10 01 00 88 22
    HEX      40 A0 48 09 01 08 21 44 29 22 08 A0 45 06 E4 8A
    HEX      C4 06 16 60 80 A0 09 40 18 0A 24 0A 16 B0 43 00
    HEX      20 BB 00 14 08 A0 60 0A C0 8F 0A 83 CA 11 44 08
    HEX      51 0A 20 26 4A 80
WRITE_ADDR_HDR:
    SUBROUTINE

    SEC
    LDA      Q6H,X
    LDA      Q7L,X
    BMI      .set_read_mode
    LDA      #$FF
    STA      Q7H,X
    CMP      Q6L,X
    PHA
    PLA

.write_sync:
    JSR      WRITE_ADDR_RET
    JSR      WRITE_ADDR_RET
    STA      Q6H,X
    CMP      Q6L,X
    NOP
    DEY
    BNE      .write_sync
    LDA      #$D5
    JSR      WRITE_BYTE3
    LDA      #$AA
    JSR      WRITE_BYTE3
    LDA      #$96
    JSR      WRITE_BYTE3
    LDA      FORMAT_VOLUME
    JSR      WRITE_DOUBLE_BYTE
    LDA      FORMAT_TRACK
    JSR      WRITE_DOUBLE_BYTE
    LDA      FORMAT_SECTOR
    JSR      WRITE_DOUBLE_BYTE
    LDA      FORMAT_VOLUME
    EOR      FORMAT_TRACK
    EOR      FORMAT_SECTOR
    PHA
    LSR
    ORA      PTR2BUF
    STA      Q6H,X
    LDA      Q6L,X
    PLA
    ORA      #$AA
    JSR      WRITE_BYTE2
    LDA      #$DE
    JSR      WRITE_BYTE3
    LDA      #$AA
    JSR      WRITE_BYTE3
    LDA      #$EB
    JSR      WRITE_BYTE3
    CLC

.set_read_mode:
    LDA      Q7L,X
    LDA      Q6L,X

WRITE_ADDR_RET:
    RTS
WRITE_DOUBLE_BYTE:
    PHA
    LSR
    ORA      PTR2BUF
    STA      Q6H,X
    CMP      Q6L,X
    PLA
    NOP
    NOP
    NOP
    ORA      #$AA

WRITE_BYTE2:
    NOP

WRITE_BYTE3:
    NOP
    PHA
    PLA
    STA      Q6H,X
    CMP      Q6L,X
    RTS
    HEX      88 A5 E8 91 A0 94 88 96
    HEX      E8 91 A0 94 88 96 91 91
    HEX      C8 94 D0 96 91 91 C8 94
    HEX      D0 96 91 A3 C8 A0 A5 85
    HEX      A4
RWTS_entry:
    ; RWTS entry point.
    SUBROUTINE

    STY      PTR2IOB
    STA      PTR2IOB+1
    LDY      #$02
    STY      RECALIBCNT
    LDY      #$04
    STY      RESEEKCNT
    LDY      #$01
    LDA      (PTR2IOB),Y
    TAX
    LDY      #$0F
    CMP      (PTR2IOB),Y
    BEQ      .sameslot
    TXA
    PHA
    LDA      (PTR2IOB),Y
    TAX
    PLA
    PHA
    STA      (PTR2IOB),Y
    LDA      Q7L,X
.ck_spin:
    LDY      #$08
    LDA      Q6L,X
.check_change:
    CMP      Q6L,X
    BNE      .ck_spin
    DEY
    BNE      .check_change
    PLA
    TAX
.sameslot:
    LDA      Q7L,X
    LDA      Q6L,X
    LDY      #$08
.strobe_again:
    LDA      Q6L,X
    PHA
    PLA
    PHA
    PLA
    STX      SLOTPG5
    CMP      Q6L,X
    BNE      .done_test
    DEY
    BNE      .strobe_again
.done_test:
    PHP
    LDA      MOTORON,X
    LDY      #$06
.move_ptrs:
    LDA      (PTR2IOB),Y
    STA      PTR2DCT-6,Y
    INY
    CPY      #$0A
    BNE      .move_ptrs
    LDY      #$03
    LDA      (PTR2DCT),Y
    STA      MOTOR_TIME+1
    LDY      #$02
    LDA      (PTR2IOB),Y
    LDY      #$10
    CMP      (PTR2IOB),Y
    BEQ      .save_drive
    STA      (PTR2IOB),Y
    PLP
    LDY      #$00
    PHP
.save_drive:
    ROR
    BCC      .use_drive2
    LDA      DRV0EN,X
    BCS      .use_drive1
.use_drive2:
    LDA      DRV1EN,X
.use_drive1:
    ROR      ZPAGE_DRIVE
    PLP
    PHP
    BNE      .was_on
    LDY      #$07
.wait_for_motor:
    JSR      ARM_MOVE_DELAY
    DEY
    BNE      .wait_for_motor
    LDX      SLOTPG5
.was_on:
    LDY      #$04
    LDA      (PTR2IOB),Y
    JSR      rwts_seek_track
    PLP
    BNE      .begin_cmd
    LDY      MOTOR_TIME+1
    BPL      .begin_cmd
.on_time_delay:
    LDY      #$12
.on_time_delay_inner:
    DEY
    BNE      .on_time_delay_inner
    INC      MOTOR_TIME
    BNE      .on_time_delay
    INC      MOTOR_TIME+1
    BNE      .on_time_delay
.begin_cmd:
    LDY      #$0C
    LDA      (PTR2IOB),Y
    BEQ      .was_seek
    CMP      #$04
    BEQ      .was_format
    ROR
    PHP
    BCS      .reset_cnt
    JSR      PRENIBBLE
.reset_cnt:
    LDY      #$30
    STY      READ_CTR
.set_x_slot:
    LDX      SLOTPG5
    JSR      READ_ADDR
    BCC      .addr_read_good
.reduce_read_cnt:
    DEC      READ_CTR
    BPL      .set_x_slot
.do_recalibrate:
    LDA      CURR_TRACK
    PHA
    LDA      #$60
    JSR      rwts_set_track
    DEC      RECALIBCNT
    BEQ      .drive_err
    LDA      #$04
    STA      RESEEKCNT
    LDA      #$00
    JSR      rwts_seek_track
    PLA
.reseek:
    JSR      rwts_seek_track
    JMP      .reset_cnt
.addr_read_good:
    LDY      TRACK_ON_DISK
    CPY      CURR_TRACK
    BEQ      .found_track
    LDA      CURR_TRACK
    PHA
    TYA
    JSR      rwts_set_track
    PLA
    DEC      RESEEKCNT
    BNE      .reseek
    BEQ      .do_recalibrate
.drive_err:
    PLA
    LDA      #$40
.to_err_rwts:
    PLP
    JMP      .rwts_err
.was_seek:
    BEQ      .rwts_exit
.was_format:
    JMP      rwts_format
.found_track:
    LDY      #$03
    LDA      (PTR2IOB),Y
    PHA
    LDA      CHECKSUM_DISK
    LDY      #$0E
    STA      (PTR2IOB),Y
    PLA
    BEQ      .found_volume
    CMP      CHECKSUM_DISK
    BEQ      .found_volume
    LDA      #$20
    BNE      .to_err_rwts
.found_volume:
    LDY      #$05
    LDA      (PTR2IOB),Y
    TAY
    LDA      PHYSECTOR,Y
    CMP      SECTOR_DSK
    BNE      .reduce_read_cnt
    PLP
    BCC      .write
    JSR      READ
    PHP
    BCS      .reduce_read_cnt
    PLP
    LDX      #$00
    STX      RWTS_SCRATCH
    JSR      POSTNIBBLE
    LDX      SLOTPG5
.rwts_exit:
    CLC
    HEX      24     ; BIT instruction skips next SEC
.rwts_err:
    SEC
    LDY      #$0D
    STA      (PTR2IOB),Y
    LDA      MOTOROFF,X
    RTS
.write:
    JSR      WRITE
    BCC      .rwts_exit
    LDA      #$10
    BCS      .rwts_err
rwts_seek_track:
    ; Determines drive type and moves disk arm
    ; to desired track.
    SUBROUTINE

    PHA
    LDY      #$01
    LDA      (PTR2DCT),Y
    ROR
    PLA
    BCC      rwts_move_arm
    ASL
    JSR      rwts_move_arm
    LSR      CURR_TRACK
    RTS
rwts_move_arm:
    ; Moves disk arm to desired track.
    SUBROUTINE

    STA      DEST_TRACK
    JSR      rwts_slot_x_to_y
    LDA      CURR_TRACK,Y
    BIT      ZPAGE_DRIVE
    BMI      .set_curr_track
    LDA      RESEEKCNT,Y
.set_curr_track:
    STA      CURR_TRACK
    LDA      DEST_TRACK
    BIT      ZPAGE_DRIVE
    BMI      .using_drive_1
    STA      RESEEKCNT,Y
    BPL      .using_drive_2
.using_drive_1:
    STA      CURR_TRACK,Y
.using_drive_2:
    JMP      SEEKABS
rwts_slot_x_to_y:
    ; Moves slot*16 in X to slot in Y.
    TXA
    LSR
    LSR
    LSR
    LSR
    TAY
    RTS
rwts_set_track:
    ; Sets track for RWTS.
    SUBROUTINE

    PHA
    LDY      #$02
    LDA      (PTR2IOB),Y
    ROR
    ROR      ZPAGE_DRIVE
    JSR      rwts_slot_x_to_y
    PLA
    ASL
    BIT      ZPAGE_DRIVE
    BMI      .store_drive_1
    STA      TRACK_FOR_DRIVE_2,Y
    BPL      .end
.store_drive_1:
    STA      TRACK_FOR_DRIVE_1,Y
.end:
    RTS
rwts_format:
    ; Formats a disk.
    SUBROUTINE

    LDY      #$03
    LDA      (PTR2IOB),Y
    STA      FORMAT_VOLUME
    LDA      #$AA
    STA      PTR2BUF
    LDY      #$56
    LDA      #$00
    STA      FORMAT_TRACK
.zbuf2:
    STA      PRIMARY_BUFF+255,Y
    DEY
    BNE      .zbuf2
.zbuf1:
    STA      PRIMARY_BUFF,Y
    DEY
    BNE      .zbuf1
    LDA      #$50
    JSR      rwts_set_track
    LDA      #$28
    STA      SYNC_CTR
.format_next_track:
    LDA      FORMAT_TRACK
    JSR      rwts_seek_track
    JSR      rwts_format_track
    LDA      #$08
    BCS      .format_err
    LDA      #$30
    STA      READ_CTR
.read_again:
    SEC
    DEC      READ_CTR
    BEQ      .format_err
    JSR      READ_ADDR
    BCS      .read_again
    LDA      SECTOR_DSK
    BNE      .read_again
    JSR      READ
    BCS      .read_again
    INC      FORMAT_TRACK
    LDA      FORMAT_TRACK
    CMP      #$23
    BCC      .format_next_track
    CLC
    BCC      .format_done
.format_err:
    LDY      #$0D
    STA      (PTR2IOB),Y
    SEC
.format_done:
    LDA      MOTOROFF,X
    RTS
rwts_format_track:
    ; Formats a track.
    SUBROUTINE

    LDA      #$00
    STA      FORMAT_SECTOR
    LDY      #$80
    BNE      .do_addr
.format_sector:
    LDY      SYNC_CTR
.do_addr:
    JSR      WRITE_ADDR_HDR
    BCS      .return
    JSR      WRITE
    BCS      .return
    INC      FORMAT_SECTOR
    LDA      FORMAT_SECTOR
    CMP      #$10
    BCC      .format_sector
    LDY      #$0F
    STY      FORMAT_SECTOR
    LDA      #$30
    STA      READ_CTR
.fill_sector_map:
    STA      SECTOR_FLAGS,Y
    DEY
    BPL      .fill_sector_map
    LDY      SYNC_CTR
.bypass_syncs:
    JSR      .return
    JSR      .return
    JSR      .return
    PHA
    PLA
    NOP
    DEY
    BNE      .bypass_syncs
    JSR      READ_ADDR
    BCS      .reread_addr
    LDA      SECTOR_DSK
    BEQ      .read_next_data_sector
    LDA      #$10
    CMP      SYNC_CTR
    LDA      SYNC_CTR
    SBC      #$01
    STA      SYNC_CTR
    CMP      #$05
    BCS      .reread_addr
    SEC
    RTS
.read_next_addr:
    JSR      READ_ADDR
    BCS      .bad_read
.read_next_data_sector:
    JSR      READ
    BCC      .check_sector_map
.bad_read:
    DEC      READ_CTR
    BNE      .read_next_addr
.reread_addr:
    JSR      READ_ADDR
    BCS      .not_last
    LDA      SECTOR_DSK
    CMP      #$0F
    BNE      .not_last
    JSR      READ
    BCC      rwts_format_track
.not_last:
    DEC      READ_CTR
    BNE      .reread_addr
    SEC
.return:
    RTS
.check_sector_map:
    LDY      SECTOR_DSK
    LDA      SECTOR_FLAGS,Y
    BMI      .bad_read
    LDA      #$FF
    STA      SECTOR_FLAGS,Y
    DEC      FORMAT_SECTOR
    BPL      .read_next_addr
    LDA      FORMAT_TRACK
    BNE      .no_track_0
    LDA      SYNC_CTR
    CMP      #$10
    BCC      .return
    DEC      SYNC_CTR
    DEC      SYNC_CTR
.no_track_0:
    CLC
    RTS
SECTOR_FLAGS:
    HEX      FF FF FF FF FF FF FF FF
    HEX      FF FF FF FF FF FF FF FF
PHYSECTOR:
    HEX      00 04 08 0C 01 05 09 0D
    HEX      02 06 0A 0E 03 07 0B 0F
RWTS_CLOBBER_LANG_CARD:
    SUBROUTINE

    JSR      SETVID
    LDA      PHASEON
    LDA      PHASEON
    LDA      #$00
    STA      $E000
    JMP      BACK_TO_BOOT2
    HEX      00 00 00
RWTS_ZERO_PATCH:
    SUBROUTINE

    STA      $1663
    STA      $1670
    STA      $1671
    RTS
RWTS_PATCH_2:
    SUBROUTINE

    JSR      $135B
    STY      $16B7
    RTS
RWTS_DISK_FULL_PATCH:
    SUBROUTINE

    JSR      $1A7E
    LDX      $1F9B
    TXS
    JSR      $0F16
    TSX
    STX      $1F9B
    LDA      #$09
    JMP      $1F85