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
DEBUG_JUMP          EQU     $7C     ; 3 bytes
SECTORS_PER_TRACK   EQU     $7F
CURR_OPCODE         EQU     $80
OPERAND_COUNT       EQU     $81
OPERAND0            EQU     $82     ; 2 bytes
OPERAND1            EQU     $84     ; 2 bytes
OPERAND2            EQU     $86     ; 2 bytes
OPERAND3            EQU     $88     ; 2 bytes
Z_PC                EQU     $8A     ; 3 bytes
ZCODE_PAGE_ADDR     EQU     $8D     ; 2 bytes
ZCODE_PAGE_VALID    EQU     $8F
PAGE_TABLE_INDEX    EQU     $90
Z_PC2_H             EQU     $91
Z_PC2_HH            EQU     $92
Z_PC2_L             EQU     $93
ZCODE_PAGE_ADDR2    EQU     $94     ; 2 bytes
ZCODE_PAGE_VALID2   EQU     $96
PAGE_TABLE_INDEX2   EQU     $97
GLOBAL_ZVARS_ADDR   EQU     $98     ; 2 bytes
LOCAL_ZVARS         EQU     $9A     ; 30 bytes
HIGH_MEM_ADDR       EQU     $B8
Z_HEADER_ADDR       EQU     $BA     ; 2 bytes
NUM_IMAGE_PAGES     EQU     $BC
NUM_PAGE_TABLE_ENTRIES EQU  $BD
FIRST_Z_PAGE        EQU     $BE
LAST_Z_PAGE         EQU     $BF
PAGE_L_TABLE        EQU     $C0     ; 2 bytes
PAGE_H_TABLE        EQU     $C2     ; 2 bytes
NEXT_PAGE_TABLE     EQU     $C4     ; 2 bytes
PREV_PAGE_TABLE     EQU     $C6     ; 2 bytes
STACK_COUNT         EQU     $C8
Z_SP                EQU     $C9     ; 2 bytes
FRAME_Z_SP          EQU     $CB     ; 2 bytes
FRAME_STACK_COUNT   EQU     $CD
SHIFT_ALPHABET      EQU     $CE
LOCKED_ALPHABET     EQU     $CF
ZDECOMPRESS_STATE   EQU     $D0
ZCHARS_L            EQU     $D1
ZCHARS_H            EQU     $D2
ZCHAR_SCRATCH1      EQU     $D3     ; 6 bytes
ZCHAR_SCRATCH2      EQU     $DA     ; 6 bytes
TOKEN_IDX           EQU     $E0
INPUT_PTR           EQU     $E1
Z_ABBREV_TABLE      EQU     $E2     ; 2 bytes
SCRATCH1            EQU     $E4     ; 2 bytes
SCRATCH2            EQU     $E6     ; 2 bytes
SCRATCH3            EQU     $E8     ; 2 bytes
SIGN_BIT            EQU     $EA
BUFF_END            EQU     $EB
BUFF_LINE_LEN       EQU     $EC
CURR_LINE           EQU     $ED
PRINTER_CSW         EQU     $EE     ; 2 bytes
TMP_Z_PC            EQU     $F0     ; 3 bytes
BUFF_AREA           EQU     $0200
RWTS                EQU     $2900
HEADER_VERSION          EQU     $00
HEADER_FLAGS1           EQU     $01
HEADER_HIMEM_BASE       EQU     $04
HEADER_INITIAL_ZPC      EQU     $06
HEADER_DICT_ADDR        EQU     $08
HEADER_OBJECT_TABLE_ADDR EQU    $0A
HEADER_GLOBALVARS_ADDR  EQU     $0C
HEADER_STATIC_MEM_BASE  EQU     $0E
HEADER_FLAGS2           EQU     $10
HEADER_ABBREVS_ADDR     EQU     $18
FIRST_OBJECT_OFFSET     EQU     $35

OBJECT_PARENT_OFFSET    EQU     $04
OBJECT_SIBLING_OFFSET   EQU     $05
OBJECT_CHILD_OFFSET     EQU     $06
OBJECT_PROPS_OFFSET     EQU     $07
VAR_CURR_ROOM       EQU     $10
VAR_SCORE           EQU     $11
VAR_MAX_SCORE       EQU     $12

    ORG         $0800

