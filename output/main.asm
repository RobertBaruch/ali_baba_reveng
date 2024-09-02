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

    ORG      $0800

main:
    SUBROUTINE

    CLD
    LDA      #$00
    LDX      #$80

.clear:
    STA      $00,X
    INX
    BNE      .clear
    LDX      #$FF
    TXS
.set_vars:
    ; Historical note: Setting PRINTER_CSW was originally a call to SINIT,
    ; "system-dependent initialization".
    LDA      #$C1
    STA      PRINTER_CSW+1
    LDA      #$00
    STA      PRINTER_CSW
    LDA      #$00
    STA      ZCODE_PAGE_VALID
    STA      ZCODE_PAGE_VALID2
    STOB     #$01, STACK_COUNT
    STOW     #$03E8, Z_SP
    STOB     #$FF, ZCHAR_SCRATCH1+6
    STOW     #$2200, PAGE_L_TABLE
    STOW     #$2280, PAGE_H_TABLE
    STOW     #$2300, NEXT_PAGE_TABLE
    STOW     #$2380, PREV_PAGE_TABLE
    LDY      #$00
    LDX      #$80       ; Max pages

.loop_inc_dec_tables:
    LDA      #$00
    STA      (PAGE_L_TABLE),Y
    STA      (PAGE_H_TABLE),Y
    TYA
    CLC
    ADC      #$01
    STA      (NEXT_PAGE_TABLE),Y
    TYA
    SEC
    SBC      #$01
    STA      (PREV_PAGE_TABLE),Y
    INY
    DEX
    BNE      .loop_inc_dec_tables
    DEY
    LDA      #$FF
    STA      (NEXT_PAGE_TABLE),Y
    STOB     #$00, FIRST_Z_PAGE
    STOB     #$7F, LAST_Z_PAGE
    STOW     #$2C00, Z_HEADER_ADDR
    JSR      do_reset_window
.read_z_image:
    MOVW     Z_HEADER_ADDR, SCRATCH2
    STOW     #$0000, SCRATCH1
    JSR      read_from_sector

    ; Historical note: The original Infocom source code did not check
    ; for an error here.

    BCC      .no_error
    JMP      main
.no_error:
    LDY      #HEADER_HIMEM_BASE+1
    LDA      #$FF
    STA      (Z_HEADER_ADDR),Y      ; low byte of high memory base always FF.
    DEY
    LDA      (Z_HEADER_ADDR),Y      ; page
    STA      NUM_IMAGE_PAGES
    INC      NUM_IMAGE_PAGES
    LDA      #$00               ; sector = 0

.read_another_sector:
    CLC                         ; ++sector
    ADC      #$01
    TAX
    ADC      Z_HEADER_ADDR+1    ; dest_addr = Z_HEADER_ADDR + 256*sector
    STA      SCRATCH2+1
    LDA      Z_HEADER_ADDR
    STA      SCRATCH2
    TXA
    CMP      NUM_IMAGE_PAGES
    BEQ      .check_debug_flag  ; done loading?
    PHA                         ; read_sector = sector
    STA      SCRATCH1
    LDA      #$00
    STA      SCRATCH1+1
    JSR      read_from_sector   ; read_from_sector(read_sector, dest_addr)

    ; Historical note: The original Infocom source code did not check
    ; for an error here.

    BCC      .no_error2
    JMP      main

.no_error2:
    PLA
    JMP      .read_another_sector
.check_debug_flag:
    LDY      #HEADER_FLAGS1
    LDA      (Z_HEADER_ADDR),Y
    AND      #$01
    EOR      #$01
    BEQ      .brk
.store_initial_z_pc:
    LDY      #HEADER_INITIAL_ZPC+1
    LDA      (Z_HEADER_ADDR),Y
    STA      Z_PC
    DEY
    LDA      (Z_HEADER_ADDR),Y
    STA      Z_PC+1
    STOB     #$00, Z_PC+2
.store_z_global_vars_addr:
    LDY      #HEADER_GLOBALVARS_ADDR+1
    LDA      (Z_HEADER_ADDR),Y
    STA      GLOBAL_ZVARS_ADDR
    DEY
    LDA      (Z_HEADER_ADDR),Y
    CLC
    ADC      Z_HEADER_ADDR+1
    STA      GLOBAL_ZVARS_ADDR+1

.store_z_abbrev_table_addr:
    LDY      #HEADER_ABBREVS_ADDR+1
    LDA      (Z_HEADER_ADDR),Y
    STA      Z_ABBREV_TABLE
    DEY
    LDA      (Z_HEADER_ADDR),Y
    CLC
    ADC      Z_HEADER_ADDR+1
    STA      Z_ABBREV_TABLE+1
    STOB     #$00, HIGH_MEM_ADDR
    LDA      NUM_IMAGE_PAGES
    CLC
    ADC      Z_HEADER_ADDR+1
    STA      HIGH_MEM_ADDR+1
    JSR      locate_last_ram_page
    SEC
    SBC      HIGH_MEM_ADDR+1
    BCC      .brk
    TAY
    INY
    STY      NUM_PAGE_TABLE_ENTRIES
    TAY
    STY      LAST_Z_PAGE
    LDA      #$FF
    STA      (NEXT_PAGE_TABLE),Y
    JMP      do_instruction

.brk:
    JSR      brk

routines_table_0op:
    WORD     instr_rtrue
    WORD     instr_rfalse
    WORD     instr_print
    WORD     instr_print_ret
    WORD     instr_nop
    WORD     instr_save
    WORD     instr_restore
    WORD     instr_restart
    WORD     instr_ret_popped
    WORD     instr_pop
    WORD     instr_quit
    WORD     instr_new_line

routines_table_1op:
    WORD     instr_jz
    WORD     instr_get_sibling
    WORD     instr_get_child
    WORD     instr_get_parent
    WORD     instr_get_prop_len
    WORD     instr_inc
    WORD     instr_dec
    WORD     instr_print_addr
    WORD     illegal_opcode
    WORD     instr_remove_obj
    WORD     instr_print_obj
    WORD     instr_ret
    WORD     instr_jump
    WORD     instr_print_paddr
    WORD     instr_load
    WORD     instr_not

routines_table_2op:
    WORD     illegal_opcode
    WORD     instr_je
    WORD     instr_jl
    WORD     instr_jg
    WORD     instr_dec_chk
    WORD     instr_inc_chk
    WORD     instr_jin
    WORD     instr_test
    WORD     instr_or
    WORD     instr_and
    WORD     instr_test_attr
    WORD     instr_set_attr
    WORD     instr_clear_attr
    WORD     instr_store
    WORD     instr_insert_obj
    WORD     instr_loadw
    WORD     instr_loadb
    WORD     instr_get_prop
    WORD     instr_get_prop_addr
    WORD     instr_get_next_prop
    WORD     instr_add
    WORD     instr_sub
    WORD     instr_mul
    WORD     instr_div
    WORD     instr_mod

routines_table_var:
    WORD     instr_call
    WORD     instr_storew
    WORD     instr_storeb
    WORD     instr_put_prop
    WORD     instr_sread
    WORD     instr_print_char
    WORD     instr_print_num
    WORD     instr_random
    WORD     instr_push
    WORD     instr_pull

do_instruction:
    SUBROUTINE

    MOVW     Z_PC, TMP_Z_PC     ; Save PC for debugging
    MOVB     Z_PC+2, TMP_Z_PC+2
    STOB     #$00, OPERAND_COUNT
    JSR      get_next_code_byte
    STA      CURR_OPCODE
    CMP      #$80           ; is 2op?
    BCS      .is_gte_80
    JMP      .do_2op

.is_gte_80:
    CMP      #$B0           ; is 1op?
    BCS      .is_gte_B0
    JMP      .do_1op

.is_gte_B0:
    CMP      #$C0           ; is 0op?
    BCC      .do_0op
    JSR      get_next_code_byte

    ; Falls through to varop handling.

    LDX      #$00               ; operand number

.get_next_operand:
    PHA                         ; save operand map
    TAY
    TXA
    PHA                         ; save operand number
    TYA
    AND      #$C0               ; check top 2 bits
    BNE      .is_01_10_11
    JSR      get_const_word            ; handle 00
    JMP      .store_operand

.is_01_10_11:
    CMP      #$80
    BNE      .is_01_11
    JSR      get_var_content           ; handle 10
    JMP      .store_operand

.is_01_11:
    CMP      #$40
    BNE      .is_11
    JSR      get_const_byte            ; handle 01
    JMP      .store_operand

.is_11:
    PLA
    PLA
    JMP      .handle_varoperand_opcode ; handle 11 (ends operand list)

.store_operand:
    PLA
    TAX
    LDA      SCRATCH2
    STA      OPERAND0,X
    LDA      SCRATCH2+1
    STA      OPERAND0+1,X
    INX
    INX
    INC      OPERAND_COUNT
    PLA                                ; shift operand map left 2 bits
    SEC
    ROL
    SEC
    ROL
    JMP      .get_next_operand
.handle_varoperand_opcode:
    STOW     routines_table_var, SCRATCH2
    LDA      CURR_OPCODE
    CMP      #$E0
    BCS      .is_vararg_instr
    JMP      .check_for_good_2op

.is_vararg_instr:
    SBC      #$E0               ; Allow only E0-E9.
    CMP      #$0A
    BCC      .opcode_table_jump
    JMP      illegal_opcode
.opcode_table_jump:
    ASL
    TAY
    LDA      (SCRATCH2),Y
    STA      SCRATCH1
    INY
    LDA      (SCRATCH2),Y
    STA      SCRATCH1+1
    JSR      DEBUG_JUMP
    JMP      (SCRATCH1)
.do_0op:
    SEC
    SBC      #$B0
    CMP      #$0C
    BCC      .load_opcode_table
    JMP      illegal_opcode

.load_opcode_table:
    PHA
    STOW     routines_table_0op, SCRATCH2
    PLA
    JMP      .opcode_table_jump
.do_1op:
    AND      #$30
    BNE      .is_90_to_AF
    JSR      get_const_word   ; Get operand for opcodes 80-8F
    JMP      .1op_arg_loaded
.is_90_to_AF:
    CMP      #$10
    BNE      .is_A0_to_AF
    JSR      get_const_byte   ; Get operand for opcodes 90-9F
    JMP      .1op_arg_loaded
.is_A0_to_AF:
    JSR      get_var_content  ; Get operand for opcodes A0-AF
.1op_arg_loaded:
    STOB     #$01, OPERAND_COUNT
    MOVW     SCRATCH2, OPERAND0
    LDA      CURR_OPCODE
    AND      #$0F
    CMP      #$10
    BCC      .go_to_1op
    JMP      illegal_opcode
.go_to_1op:
    PHA
    STOW     routines_table_1op, SCRATCH2
    PLA
    JMP      .opcode_table_jump
.do_2op:
    AND      #$40
    BNE      .first_arg_is_var
    JSR      get_const_byte
    JMP      .get_next_arg

.first_arg_is_var:
    JSR      get_var_content

.get_next_arg:
    MOVW     SCRATCH2, OPERAND0
    LDA      CURR_OPCODE
    AND      #$20
    BNE      .second_arg_is_var
    JSR      get_const_byte
    JMP      .store_second_arg

.second_arg_is_var:
    JSR      get_var_content

.store_second_arg:
    MOVW     SCRATCH2, OPERAND1
    STOB     #$02, OPERAND_COUNT
    LDA      CURR_OPCODE

.check_for_good_2op:
    AND      #$1F
    CMP      #$19
    BCC      .go_to_op2
    JMP      illegal_opcode
.go_to_op2:
    PHA
    STOW     routines_table_2op, SCRATCH2
    PLA
    JMP      .opcode_table_jump
get_const_byte:
    SUBROUTINE

    JSR      get_next_code_byte
    STA      SCRATCH2
    STOB     #$00, SCRATCH2+1
    RTS
get_const_word:
    SUBROUTINE

    JSR      get_next_code_byte
    PHA
    JSR      get_next_code_byte
    STA      SCRATCH2
    PLA
    STA      SCRATCH2+1
    RTS
var_get:
    SUBROUTINE

    ORA      #$00
    BEQ      pop_push
    JMP      get_nonstack_var
var_put:
    SUBROUTINE

    ORA      #$00
    BEQ      .pop_push
    JMP      store_var2

pop_push:
    JSR      pop
    JMP      push

.pop_push:
    PSHW     SCRATCH2
    JSR      pop
    PULW     SCRATCH2
    JMP      push
get_var_content:
    SUBROUTINE

    JSR      get_next_code_byte         ; A = get_next_code_byte<Z_PC>
    ORA      #$00                       ; if (!A) get_top_of_stack
    BEQ      get_top_of_stack

get_nonstack_var:
    SUBROUTINE

    CMP      #$10                       ; if (A < #$10) {
    BCS      .compute_global_var_index
    SEC                                 ;   SCRATCH2 = LOCAL_ZVARS[A - 1]
    SBC      #$01
    ASL
    TAX
    LDA      LOCAL_ZVARS,X
    STA      SCRATCH2+1
    INX
    LDA      LOCAL_ZVARS,X
    STA      SCRATCH2
    RTS                                 ;   return
                                        ; }

.compute_global_var_index:
    SEC                                 ; var_ptr = 2 * (A - #$10)
    SBC      #$10
    ASL
    STA      SCRATCH1
    LDA      #$00
    ROL
    STA      SCRATCH1+1

.get_global_var_addr:
    ; var_ptr += GLOBAL_ZVARS_ADDR
    ADDW     GLOBAL_ZVARS_ADDR, SCRATCH1, SCRATCH1

.get_global_var_value:
    LDY      #$00                       ; SCRATCH2 = *var_ptr
    LDA      (SCRATCH1),Y
    STA      SCRATCH2+1
    INY
    LDA      (SCRATCH1),Y
    STA      SCRATCH2
    RTS                                 ; return

get_top_of_stack:
    SUBROUTINE

    JSR      pop                        ; SCRATCH2 = pop()
    RTS                                 ; return
store_zero_and_next:
    SUBROUTINE

    LDA      #$00

store_A_and_next:
    SUBROUTINE

    STA      SCRATCH2
    STOB     #$00, SCRATCH2+1

store_and_next:
    SUBROUTINE

    JSR      store_var
    JMP      do_instruction
store_var:
    SUBROUTINE

    PSHW     SCRATCH2               ; A = get_next_code_byte()
    JSR      get_next_code_byte
    TAX
    PULW     SCRATCH2
    TXA

store_var2:
    SUBROUTINE

    ORA      #$00
    BNE      .nonstack
    JMP      push

.nonstack:
    CMP      #$10
    BCS      .global_var
    SEC
    SBC      #$01
    ASL
    TAX
    LDA      SCRATCH2+1
    STA      LOCAL_ZVARS,X
    INX
    LDA      SCRATCH2
    STA      LOCAL_ZVARS,X
    RTS

.global_var:
    SEC
    SBC      #$10
    ASL
    STA      SCRATCH1
    LDA      #$00
    ROL
    STA      SCRATCH1+1
    ADDW     GLOBAL_ZVARS_ADDR, SCRATCH1, SCRATCH1
    LDY      #$00
    LDA      SCRATCH2+1
    STA      (SCRATCH1),Y
    INY
    LDA      SCRATCH2
    STA      (SCRATCH1),Y
    RTS
branch:
    SUBROUTINE

    JSR      get_next_code_byte
    ORA      #$00
    BMI      .do_branch
    BPL      .no_branch     ; unconditional

negated_branch:
    JSR      get_next_code_byte
    ORA      #$00
    BPL      .do_branch
.no_branch:
    AND      #$40
    BNE      .next
    JSR      get_next_code_byte

.next:
    JMP      do_instruction
.do_branch:
    TAX
    AND      #$40
    BEQ      .get_14_bit_offset

.offset_is_6_bits:
    TXA
    AND      #$3F
    STA      SCRATCH2
    LDA      #$00
    STA      SCRATCH2+1
    JMP      .check_for_return_false

.get_14_bit_offset:
    TXA
    AND      #$3F
    PHA
    JSR      get_next_code_byte
    STA      SCRATCH2
    PLA
    STA      SCRATCH2+1
    AND      #$20
    BEQ      .check_for_return_false
    LDA      SCRATCH2+1
    ORA      #$C0
    STA      SCRATCH2+1
.check_for_return_false:
    LDA      SCRATCH2+1
    ORA      SCRATCH2
    BEQ      instr_rfalse
    LDA      SCRATCH2
    SEC
    SBC      #$01
    STA      SCRATCH2
    BCS      .check_for_return_true
    DEC      SCRATCH2+1

.check_for_return_true:
    LDA      SCRATCH2+1
    ORA      SCRATCH2
    BEQ      instr_rtrue
branch_to_offset:
    SUBROUTINE

    SUBB     SCRATCH2, #$01
    LDA      SCRATCH2+1
    STA      SCRATCH1
    ASL
    LDA      #$00
    ROL
    STA      SCRATCH1+1
    LDA      Z_PC
    CLC
    ADC      SCRATCH2
    BCC      .continue2
    INC      SCRATCH1
    BNE      .continue2
    INC      SCRATCH1+1

.continue2:
    STA      Z_PC
    LDA      SCRATCH1+1
    ORA      SCRATCH1
    BEQ      .next

    CLC
    LDA      SCRATCH1
    ADC      Z_PC+1
    STA      Z_PC+1
    LDA      SCRATCH1+1
    ADC      Z_PC+2
    AND      #$01
    STA      Z_PC+2
    LDA      #$00
    STA      ZCODE_PAGE_VALID
    JMP      do_instruction

.next:
    JMP      do_instruction
instr_rtrue:
    SUBROUTINE

    LDA      #$01
ret_a:
    STA      OPERAND0
    LDA      #$00
    STA      OPERAND0+1
    JMP      instr_ret
instr_rfalse:
    SUBROUTINE

    LDA      #$00
    JMP      ret_a
instr_print:
    SUBROUTINE

    JSR      print_string_literal
    JMP      do_instruction
print_string_literal:
    SUBROUTINE

    MOVB     Z_PC, Z_PC2_L
    MOVB     Z_PC+1, Z_PC2_H
    MOVB     Z_PC+2, Z_PC2_HH
    STOB     #$00, ZCODE_PAGE_VALID2
    JSR      print_zstring
    MOVB     Z_PC2_L, Z_PC
    MOVB     Z_PC2_H, Z_PC+1
    MOVB     Z_PC2_HH, Z_PC+2
    MOVB     ZCODE_PAGE_VALID2, ZCODE_PAGE_VALID
    MOVW     ZCODE_PAGE_ADDR2, ZCODE_PAGE_ADDR
    RTS
instr_print_ret:
    SUBROUTINE

    JSR      print_string_literal
    LDA      #$0D
    JSR      buffer_char
    LDA      #$0A
    JSR      buffer_char
    JMP      instr_rtrue
instr_nop:
    SUBROUTINE

    JMP      do_instruction
instr_ret_popped:
    SUBROUTINE

    JSR      pop
    MOVW     SCRATCH2, OPERAND0
    JMP      instr_ret
instr_pop:
    SUBROUTINE

    JSR      pop
    JMP      do_instruction
instr_new_line:
    SUBROUTINE

    LDA      #$0D
    JSR      buffer_char
    LDA      #$0A
    JSR      buffer_char
    JMP      do_instruction
instr_jz:
    SUBROUTINE

    LDA      OPERAND0+1
    ORA      OPERAND0
    BEQ      take_branch
    JMP      negated_branch

take_branch:
    JMP      branch
instr_get_sibling:
    SUBROUTINE

    LDA      OPERAND0
    JSR      get_object_addr
    LDY      #OBJECT_SIBLING_OFFSET
    JMP      push_and_check_obj
instr_get_child:
    LDA      OPERAND0
    JSR      get_object_addr
    LDY      #OBJECT_CHILD_OFFSET

push_and_check_obj:
    LDA      (SCRATCH2),Y
    PHA
    STA      SCRATCH2
    LDA      #$00
    STA      SCRATCH2+1
    JSR      store_var    ; store in var of next code byte.
    PLA
    ORA      #$00
    BNE      take_branch
    JMP      negated_branch
instr_get_parent:
    SUBROUTINE

    LDA      OPERAND0
    JSR      get_object_addr
    LDY      #OBJECT_PARENT_OFFSET
    LDA      (SCRATCH2),Y
    STA      SCRATCH2
    LDA      #$00
    STA      SCRATCH2+1
    JMP      store_and_next
instr_get_prop_len:
    CLC
    LDA      OPERAND0
    ADC      Z_HEADER_ADDR
    STA      SCRATCH2
    LDA      OPERAND0+1
    ADC      Z_HEADER_ADDR+1
    STA      SCRATCH2+1
    LDA      SCRATCH2
    SEC
    SBC      #$01
    STA      SCRATCH2
    BCS      .continue
    DEC      SCRATCH2+1

.continue:
    LDY      #$00
    JSR      get_property_len
    CLC
    ADC      #$01
    JMP      store_A_and_next
instr_inc:
    SUBROUTINE

    JSR      inc_var
    JMP      do_instruction
instr_dec:
    SUBROUTINE

    JSR      dec_var
    JMP      do_instruction
inc_var:
    SUBROUTINE

    LDA      OPERAND0
    JSR      var_get
    INCW     SCRATCH2
inc_var_continue:
    PSHW     SCRATCH2
    LDA      OPERAND0
    JSR      var_put
    PULW     SCRATCH2
    RTS
dec_var:
    SUBROUTINE

    LDA      OPERAND0
    JSR      var_get
    SUBB     SCRATCH2, #$01
    JMP      inc_var_continue
instr_print_addr:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH2
    JSR      load_address
    JMP      print_zstring_and_next
illegal_opcode:
    SUBROUTINE

    JSR      brk
instr_remove_obj:
    SUBROUTINE

    JSR      remove_obj
    JMP      do_instruction
remove_obj:
    SUBROUTINE

    LDA      OPERAND0               ; obj_ptr = get_object_addr<obj_num>
    JSR      get_object_addr
    LDY      #OBJECT_PARENT_OFFSET  ; A = obj_ptr->parent
    LDA      (SCRATCH2),Y
    BNE      .continue              ; if (!A) return
    RTS

.continue:
    TAX                             ; save obj_ptr
    PSHW     SCRATCH2
    TXA
    JSR      get_object_addr        ; parent_ptr = get_object_addr<A>
    LDY      #OBJECT_CHILD_OFFSET   ; child_num = parent_ptr->child
    LDA      (SCRATCH2),Y
    CMP      OPERAND0               ; if (child_num != obj_num) loop
    BNE      .loop
    PULW     SCRATCH1               ; restore obj_ptr
    PSHW     SCRATCH1
    LDY      #OBJECT_SIBLING_OFFSET ; A = obj_ptr->next
    LDA      (SCRATCH1),Y
    LDY      #OBJECT_CHILD_OFFSET   ; parent_ptr->child = A
    STA      (SCRATCH2),Y
    JMP      .detach
.loop:
    JSR      get_object_addr        ; child_ptr = get_object_addr<child_num>
    LDY      #OBJECT_SIBLING_OFFSET ; child_num = child_ptr->next
    LDA      (SCRATCH2),Y
    CMP      OPERAND0               ; if (child_num != obj_num) loop
    BNE      .loop
    PULW     SCRATCH1               ; restore obj_ptr
    PSHW     SCRATCH1
    LDA      (SCRATCH1),Y           ; child_ptr->next = obj_ptr->next
    STA      (SCRATCH2),Y

.detach:
    PULW     SCRATCH2               ; restore obj_ptr
    LDY      #OBJECT_PARENT_OFFSET  ; obj_ptr->parent = 0
    LDA      #$00
    STA      (SCRATCH2),Y
    INY
    STA      (SCRATCH2),Y
    RTS                      ; detach
instr_print_obj:
    SUBROUTINE

    LDA      OPERAND0
    JSR      print_obj_in_A
    JMP      do_instruction
print_obj_in_A:
    JSR      get_object_addr        ; obj_ptr = get_object_addr<A>
    LDY      #OBJECT_PROPS_OFFSET   ; props_ptr = obj_ptr->props
    LDA      (SCRATCH2),Y
    STA      SCRATCH1+1
    INY
    LDA      (SCRATCH2),Y
    STA      SCRATCH1
    MOVW     SCRATCH1, SCRATCH2
    INCW     SCRATCH2               ; ++props_ptr
    JSR      load_address           ; Z_PC2 = props_ptr
    JMP      print_zstring          ; print_zstring<Z_PC2>
instr_ret:
    SUBROUTINE

    MOVW     FRAME_Z_SP, Z_SP
    MOVB     FRAME_STACK_COUNT, STACK_COUNT
    JSR      pop
    LDA      SCRATCH2
    BEQ      .done_locals
    STOW     GLOBAL_ZVARS_ADDR, SCRATCH1    ; ptr = GLOBAL_ZVARS_ADDR
    MOVB     SCRATCH2, SCRATCH3             ; count = STRATCH2
    ASL                                     ; ptr += 2 * count
    ADDA     SCRATCH1
.loop:
    JSR      pop                ; SCRATCH2 = pop()
    LDY      #$01               ; *ptr = SCRATCH2
    LDA      SCRATCH2
    STA      (SCRATCH1),Y
    DEY
    LDA      SCRATCH2+1
    STA      (SCRATCH1),Y
    SUBB     SCRATCH1, #$02     ; ptr -= 2
    DEC      SCRATCH3           ; --count
    BNE      .loop
.done_locals:
    JSR      pop
    MOVW     SCRATCH2, Z_PC+1
    JSR      pop
    MOVW     SCRATCH2, FRAME_Z_SP
    JSR      pop
    MOVB     SCRATCH2+1, Z_PC
    MOVB     SCRATCH2, FRAME_STACK_COUNT
    STOB     #$00, ZCODE_PAGE_VALID
    MOVW     OPERAND0, SCRATCH2
    JMP      store_and_next
instr_jump:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH2
    SUBB     SCRATCH2, #$01
    JMP      branch_to_offset
instr_print_paddr:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH2     ; Z_PC2 <- OPERAND0 * 2
    JSR      load_packed_address

    ; Falls through to print_zstring_and_next
print_zstring_and_next:
    SUBROUTINE

    JSR      print_zstring
    JMP      do_instruction
instr_load:
    SUBROUTINE

    LDA      OPERAND0
    JSR      var_get
    JMP      store_and_next
instr_not:
    SUBROUTINE

    LDA      OPERAND0
    EOR      #$FF
    STA      SCRATCH2
    LDA      OPERAND0+1
    EOR      #$FF
    STA      SCRATCH2+1
    JMP      store_and_next
instr_jl:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH2
    MOVW     OPERAND1, SCRATCH1
    JSR      cmp16
    BCC      stretch_to_branch
    JMP      negated_branch
instr_jg:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH1
    MOVW     OPERAND1, SCRATCH2
    JSR      cmp16
    BCC      stretch_to_branch
    JMP      negated_branch
instr_dec_chk:
    SUBROUTINE

    JSR      dec_var
    MOVW     OPERAND1, SCRATCH1
    JMP      do_chk
instr_inc_chk:
    JSR      inc_var
    MOVW     SCRATCH2, SCRATCH1
    MOVW     OPERAND1, SCRATCH2

do_chk:
    JSR      cmp16
    BCC      stretch_to_branch
    JMP      negated_branch

stretch_to_branch:
    JMP      branch
instr_jin:
    SUBROUTINE

    LDA      OPERAND0
    JSR      get_object_addr
    LDY      #OBJECT_PARENT_OFFSET
    LDA      OPERAND1
    CMP      (SCRATCH2),Y
    BEQ      stretch_to_branch
    JMP      negated_branch
instr_test:
    SUBROUTINE

    MOVB     OPERAND1+1, SCRATCH2+1
    AND      OPERAND0+1
    STA      SCRATCH1+1
    MOVB     OPERAND1, SCRATCH2
    AND      OPERAND0
    STA      SCRATCH1
    JSR      cmpu16
    BEQ      stretch_to_branch
    JMP      negated_branch
instr_or:
    SUBROUTINE

    LDA      OPERAND1+1
    ORA      OPERAND0+1
    STA      SCRATCH2+1
    LDA      OPERAND1
    ORA      OPERAND0
    STA      SCRATCH2
    JMP      store_and_next
instr_and:
    SUBROUTINE

    LDA      OPERAND1+1
    AND      OPERAND0+1
    STA      SCRATCH2+1
    LDA      OPERAND1
    AND      OPERAND0
    STA      SCRATCH2
    JMP      store_and_next
instr_test_attr:
    SUBROUTINE

    JSR      attr_ptr_and_mask
    LDA      SCRATCH1+1
    AND      SCRATCH3+1
    STA      SCRATCH1+1
    LDA      SCRATCH1
    AND      SCRATCH3
    ORA      SCRATCH1+1
    BNE      stretch_to_branch
    JMP      negated_branch
instr_set_attr:
    SUBROUTINE

    JSR      attr_ptr_and_mask
    LDY      #$01
    LDA      SCRATCH1
    ORA      SCRATCH3
    STA      (SCRATCH2),Y
    DEY
    LDA      SCRATCH1+1
    ORA      SCRATCH3+1
    STA      (SCRATCH2),Y
    JMP      do_instruction
instr_clear_attr:
    SUBROUTINE

    JSR      attr_ptr_and_mask
    LDY      #$01
    LDA      SCRATCH3
    EOR      #$FF
    AND      SCRATCH1
    STA      (SCRATCH2),Y
    DEY
    LDA      SCRATCH3+1
    EOR      #$FF
    AND      SCRATCH1+1
    STA      (SCRATCH2),Y
    JMP      do_instruction
instr_store:
    SUBROUTINE

    MOVW     OPERAND1, SCRATCH2
    LDA      OPERAND0

stretch_var_put:
    JSR      var_put
    JMP      do_instruction
instr_insert_obj:
    JSR      remove_obj             ; remove_obj<OPERAND0>
    LDA      OPERAND0
    JSR      get_object_addr        ; obj_ptr = get_object_addr<OPERAND0>
    PSHW     SCRATCH2
    LDY      #OBJECT_PARENT_OFFSET
    LDA      OPERAND1
    STA      (SCRATCH2),Y           ; obj_ptr->parent = OPERAND1
    JSR      get_object_addr        ; dest_ptr = get_object_addr<OPERAND1>
    LDY      #OBJECT_CHILD_OFFSET   ; tmp = dest_ptr->child
    LDA      (SCRATCH2),Y
    TAX
    LDA      OPERAND0               ; dest_ptr->child = OPERAND0
    STA      (SCRATCH2),Y
    PULW     SCRATCH2
    TXA
    BEQ      .continue
    LDY      #OBJECT_SIBLING_OFFSET ; obj_ptr->sibling = tmp
    STA      (SCRATCH2),Y

.continue:
    JMP      do_instruction
instr_loadw:
    SUBROUTINE

    ASL      OPERAND1               ; OPERAND1 *= 2
    ROL      OPERAND1+1
    ADDW     OPERAND1, OPERAND0, SCRATCH2
    JSR      load_address
    JSR      get_next_code_word
    JMP      store_and_next
instr_loadb:
    SUBROUTINE

    ADDW     OPERAND1, OPERAND0, SCRATCH2   ; SCRATCH2 = OPERAND0 + OPERAND1
    JSR      load_address                   ; Z_PC2 = SCRATCH2
    JSR      get_next_code_byte2            ; A = *Z_PC2
    STA      SCRATCH2                       ; SCRATCH2 = uint16(A)
    LDA      #$00
    STA      SCRATCH2+1
    JMP      store_and_next                 ; store_and_next(SCRATCH2)
instr_get_prop:
    SUBROUTINE

    JSR      get_property_ptr

.loop:
    JSR      get_property_num
    CMP      OPERAND1
    BEQ      .found
    BCC      .get_default
    JSR      next_property
    JMP      .loop
.get_default:
    LDY      #HEADER_OBJECT_TABLE_ADDR+1
    CLC
    LDA      (Z_HEADER_ADDR),Y
    ADC      Z_HEADER_ADDR
    STA      SCRATCH1
    DEY
    LDA      (Z_HEADER_ADDR),Y
    ADC      Z_HEADER_ADDR+1
    STA      SCRATCH1+1             ; table_ptr
    LDA      OPERAND1               ; SCRATCH2 <- table_ptr[2*OPERAND1]
    ASL
    TAY
    DEY
    LDA      (SCRATCH1),Y
    STA      SCRATCH2
    DEY
    LDA      (SCRATCH1),Y
    STA      SCRATCH2+1
    JMP      store_and_next
.found:
    JSR      get_property_len
    INY
    CMP      #$00
    BEQ      .byte_prop
    CMP      #$01
    BEQ      .word_prop
    JSR      brk

.word_prop:
    LDA      (SCRATCH2),Y
    STA      SCRATCH1+1
    INY
    LDA      (SCRATCH2),Y
    STA      SCRATCH1
    MOVW     SCRATCH1, SCRATCH2
    JMP      store_and_next

.byte_prop:
    LDA      (SCRATCH2),Y
    STA      SCRATCH2
    LDA      #$00
    STA      SCRATCH2+1
    JMP      store_and_next
instr_get_prop_addr:
    SUBROUTINE

    JSR      get_property_ptr

.loop:
    JSR      get_property_num
    CMP      OPERAND1
    BEQ      .found
    BCS      .next
    JMP      store_zero_and_next

.next:
    JSR      next_property
    JMP      .loop

.found:
    INCW     SCRATCH2
    CLC
    TYA
    ADDAC    SCRATCH2
    SUBW     SCRATCH2, Z_HEADER_ADDR, SCRATCH2
    JMP      store_and_next
instr_get_next_prop:
    SUBROUTINE

    JSR      get_property_ptr
    LDA      OPERAND1
    BEQ      .store

.loop:
    JSR      get_property_num
    CMP      OPERAND1
    BEQ      .found
    BCS      .continue
    JMP      store_zero_and_next

.continue:
    JSR      next_property
    JMP      .loop

.store:
    JSR      get_property_num
    JMP      store_A_and_next

.found:
    JSR      next_property
    JMP      .store
instr_add:
    SUBROUTINE

    ADDW     OPERAND0, OPERAND1, SCRATCH2
    JMP      store_and_next
instr_sub:
    SUBROUTINE

    SUBW     OPERAND0, OPERAND1, SCRATCH2
    JMP      store_and_next
instr_mul:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH2
    MOVW     OPERAND1, SCRATCH1
    JSR      check_sign
    LDA      SCRATCH1+1
    BNE      .do_mult
    LDA      SCRATCH1
    CMP      #$02
    BEQ      .shortcut_x2
    CMP      #$04
    BEQ      .shortcut_x4

.do_mult:
    JSR      mulu16

stretch_set_sign:
    JSR      set_sign
    JMP      store_and_next

.shortcut_x4:
    ASL      SCRATCH2
    ROL      SCRATCH2+1

.shortcut_x2:
    ASL      SCRATCH2
    ROL      SCRATCH2+1
    JMP      stretch_set_sign
instr_div:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH2
    MOVW     OPERAND1, SCRATCH1
    JSR      check_sign
    LDA      SCRATCH1+1
    BNE      .do_div
    LDA      SCRATCH1
    CMP      #$02
    BEQ      .shortcut_div2
    CMP      #$04
    BEQ      .shortcut_div4

.do_div:
    JSR      divu16
    JMP      stretch_set_sign

.shortcut_div4:
    LSR      SCRATCH2+1
    ROR      SCRATCH2

.shortcut_div2:
    LSR      SCRATCH2+1
    ROR      SCRATCH2
    JMP      stretch_set_sign
instr_mod:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH2
    MOVW     OPERAND1, SCRATCH1
    JSR      check_sign
    JSR      divu16
    MOVW     SCRATCH1, SCRATCH2
    JMP      store_and_next
instr_je:
    SUBROUTINE

    LDX      OPERAND_COUNT
    DEX
    BNE      .check_second
    JSR      brk
.check_second:
    LDA      OPERAND0
    CMP      OPERAND1
    BNE      .check_next
    LDA      OPERAND0+1
    CMP      OPERAND1+1
    BEQ      .branch

.check_next:
    DEX
    BEQ      .neg_branch
    LDA      OPERAND0
    CMP      OPERAND0+4
    BNE      .check_next2
    LDA      OPERAND0+1
    CMP      OPERAND0+5
    BEQ      .branch

.check_next2:
    DEX
    BEQ      .neg_branch
    LDA      OPERAND0
    CMP      OPERAND0+6
    BNE      .check_second      ; why not just go to .neg_branch?
    LDA      OPERAND0+1
    CMP      OPERAND0+7
    BEQ      .branch

.neg_branch:
    JMP      negated_branch

.branch:
    JMP      branch
instr_call:
    LDA      OPERAND0
    ORA      OPERAND0+1
    BNE      .push_frame
    STOW     #$0000, SCRATCH2
    JMP      store_and_next
.push_frame:
    MOVB     FRAME_STACK_COUNT, SCRATCH2
    MOVB     Z_PC, SCRATCH2+1
    JSR      push
    MOVW     FRAME_Z_SP, SCRATCH2
    JSR      push
    MOVW     Z_PC+1, SCRATCH2
    JSR      push
    STOB     #$00, ZCODE_PAGE_VALID
    LDA      OPERAND0
    ASL
    STA      Z_PC
    LDA      OPERAND0+1
    ROL
    STA      Z_PC+1
    LDA      #$00
    ROL
    STA      Z_PC+2
    JSR      get_next_code_byte     ; local_var_count = get_next_code_byte()
    PHA                             ; Save local_var_count
    ORA      #$00
    BEQ      .after_loop2
    LDX      #$00                   ; X = 0

.push_and_init_local_vars:
    PHA                             ; Save local_var_count
    LDA      LOCAL_ZVARS,X          ; Push LOCAL_ZVAR[X] onto the stack
    STA      SCRATCH2+1
    INX
    LDA      LOCAL_ZVARS,X
    STA      SCRATCH2
    DEX
    TXA
    PHA
    JSR      push

    JSR      get_next_code_byte     ; SCRATCH2 = next init val
    PHA
    JSR      get_next_code_byte
    STA      SCRATCH2
    PLA
    STA      SCRATCH2+1

    PLA                             ; Restore local_var_count
    TAX
    LDA      SCRATCH2+1             ; LOCAL_ZVARS[X] = SCRATCH2
    STA      LOCAL_ZVARS,X
    INX
    LDA      SCRATCH2
    STA      LOCAL_ZVARS,X
    INX                             ; Increment X
    PLA                             ; Decrement local_var_count
    SEC
    SBC      #$01
    BNE      .push_and_init_local_vars  ; Loop until no more vars
.after_loop2:
    LDA      OPERAND_COUNT          ; count = OPERAND_COUNT - 1
    STA      SCRATCH3
    DEC      SCRATCH3
    BEQ      .done_init_local_vars  ; if (!count) .done_init_local_vars

    STOB     #$00, SCRATCH1         ; operand = 0
    STOB     #$00, SCRATCH2         ; zvar = 0

.loop:
    LDX      SCRATCH1               ; LOCAL_ZVARS[zvar] = OPERANDS[operand+1]
    LDA      OPERAND1+1,X           ; high byte first
    LDX      SCRATCH2
    STA      LOCAL_ZVARS,X
    INC      SCRATCH2
    LDX      SCRATCH1
    LDA      OPERAND1,X
    LDX      SCRATCH2
    STA      LOCAL_ZVARS,X
    INC      SCRATCH2               ; ++zvar
    INC      SCRATCH1               ; ++operand
    INC      SCRATCH1
    DEC      SCRATCH3               ; --count
    BNE      .loop                  ; if (count) .loop
.done_init_local_vars:
    PULB     SCRATCH2               ; Restore local_var_count
    JSR      push                   ; Push local_var_count
    MOVB     STACK_COUNT, FRAME_STACK_COUNT
    MOVW     Z_SP, FRAME_Z_SP
    JMP      do_instruction
instr_storew:
    SUBROUTINE

    LDA      OPERAND1       ; SCRATCH2 = Z_HEADER_ADDR + OPERAND0 + 2*OPERAND1
    ASL
    ROL      OPERAND1+1
    CLC
    ADC      OPERAND0
    STA      SCRATCH2
    LDA      OPERAND1+1
    ADC      OPERAND0+1
    STA      SCRATCH2+1
    ADDW     SCRATCH2, Z_HEADER_ADDR, SCRATCH2
    LDY      #$00
    LDA      OPERAND2+1
    STA      (SCRATCH2),Y
    INY
    LDA      OPERAND2
    STA      (SCRATCH2),Y
    JMP      do_instruction
instr_storeb:
    SUBROUTINE

    LDA      OPERAND1       ; SCRATCH2 = Z_HEADER_ADDR + OPERAND0 + OPERAND1
    CLC
    ADC      OPERAND0
    STA      SCRATCH2
    LDA      OPERAND1+1
    ADC      OPERAND0+1
    STA      SCRATCH2+1
    ADDW     SCRATCH2, Z_HEADER_ADDR, SCRATCH2
    LDY      #$00
    LDA      OPERAND2
    STA      (SCRATCH2),Y
    JMP      do_instruction
instr_put_prop:
    SUBROUTINE

    JSR      get_property_ptr

.loop:
    JSR      get_property_num
    CMP      OPERAND1
    BEQ      .found
    BCS      .continue
    JSR      brk

.continue:
    JSR      next_property
    JMP      .loop

.found:
    JSR      get_property_len
    INY
    CMP      #$00
    BEQ      .byte_property
    CMP      #$01
    BEQ      .word_property
    JSR      brk

.word_property:
    LDA      OPERAND2+1
    STA      (SCRATCH2),Y
    INY
    LDA      OPERAND2
    STA      (SCRATCH2),Y
    JMP      do_instruction

.byte_property:
    LDA      OPERAND2
    STA      (SCRATCH2),Y
    JMP      do_instruction
instr_sread:
    SUBROUTINE

    JSR      print_status_line
    ADDW     OPERAND0, Z_HEADER_ADDR, OPERAND0  ; text buffer
    ADDW     OPERAND1, Z_HEADER_ADDR, OPERAND1  ; parse buffer
    JSR      read_line      ; SCRATCH3H = read_line() (input_count)
    STA      SCRATCH3+1
    STOB     #$00, SCRATCH3 ; SCRATCH3L = 0  (char count)
    LDY      #$01
    LDA      #$00           ; store 0 in the parse buffer + 1.
    STA      (OPERAND1),Y
    STOB     #$02, TOKEN_IDX
    STOB     #$01, INPUT_PTR
.loop_word:
    LDY      #$00           ; if parsebuf[0] == parsebuf[1] do_instruction
    LDA      (OPERAND1),Y
    INY
    CMP      (OPERAND1),Y
    BNE      .not_end1
    JMP      do_instruction
.not_end1:
    LDA      SCRATCH3+1     ; if input_count == char_count == 0 do_instruction
    ORA      SCRATCH3
    BNE      .not_end2
    JMP      do_instruction
.not_end2:
    LDA      SCRATCH3       ; if char_count != 6 .not_min_compress_size
    CMP      #$06
    BNE      .not_min_compress_size
    JSR      skip_separators
.not_min_compress_size:
    LDA      SCRATCH3
    BNE      .not_separator
    LDY      #$06
    LDX      #$00

.clear:
    LDA      #$00
    STA      ZCHAR_SCRATCH1,X
    INX
    DEY
    BNE      .clear
    LDA      INPUT_PTR          ; parsebuf[TOKEN_IDX+3] = INPUT_PTR
    LDY      TOKEN_IDX
    INY
    INY
    INY
    STA      (OPERAND1),Y
    LDY      INPUT_PTR          ; is_dict_separator(textbuf[INPUT_PTR])
    LDA      (OPERAND0),Y
    JSR      is_dict_separator
    BCS      .is_dict_separator
    LDY      INPUT_PTR          ; is_std_separator(textbuf[INPUT_PTR])
    LDA      (OPERAND0),Y
    JSR      is_std_separator
    BCC      .not_separator
    INC      INPUT_PTR          ; ++INPUT_PTR
    DEC      SCRATCH3+1         ; --input_count
    JMP      .loop_word
.not_separator:
    LDA      SCRATCH3+1
    BEQ      .search
    LDY      INPUT_PTR          ; is_separator(textbuf[INPUT_PTR])
    LDA      (OPERAND0),Y
    JSR      is_separator
    BCS      .search
    LDY      INPUT_PTR          ; ZCHAR_SCRATCH1[char_count] = textbuf[INPUT_PTR]
    LDA      (OPERAND0),Y
    LDX      SCRATCH3
    STA      ZCHAR_SCRATCH1,X
    DEC      SCRATCH3+1         ; --input_count
    INC      SCRATCH3           ; ++char_count
    INC      INPUT_PTR          ; ++INPUT_PTR
    JMP      .loop_word
.is_dict_separator:
    STA      ZCHAR_SCRATCH1
    INC      SCRATCH3
    DEC      SCRATCH3+1
    INC      INPUT_PTR
.search:
    LDA      SCRATCH3
    BEQ      .loop_word
    LDA      SCRATCH3+1     ; Save input_count
    PHA
    LDY      TOKEN_IDX      ; parsebuf[TOKEN_IDX+2] = char_count
    INY
    INY
    LDA      SCRATCH3
    STA      (OPERAND1),Y
    JSR      ascii_to_zchar
    JSR      match_dictionary_word
    LDY      TOKEN_IDX              ; parsebuf[TOKEN_IDX] = entry_addr
    LDA      SCRATCH1+1
    STA      (OPERAND1),Y
    INY
    LDA      SCRATCH1
    STA      (OPERAND1),Y

    INY                             ; TOKEN_IDX += 4
    INY
    INY
    STY      TOKEN_IDX

    LDY      #$01                   ; ++parsebuf[1]
    LDA      (OPERAND1),Y
    CLC
    ADC      #$01
    STA      (OPERAND1),Y

    PLA
    STA      SCRATCH3+1
    STOB     #$00, SCRATCH3
    JMP      .loop_word
skip_separators:
    SUBROUTINE

    LDA      SCRATCH3+1
    BNE      .not_end
    RTS

.not_end:
    LDY      INPUT_PTR
    LDA      (OPERAND0),Y
    JSR      is_separator
    BCC      .not_separator
    RTS

.not_separator:
    INC      INPUT_PTR
    DEC      SCRATCH3+1
    INC      SCRATCH3
    JMP      skip_separators
SEPARATORS_TABLE:
    DC       #$20, #$2E, #$2C, #$3F, #$0D, #$0A, #$09, #$0C

is_separator:
    SUBROUTINE

    JSR      is_dict_separator
    BCC      is_std_separator
    RTS

is_std_separator:
    SUBROUTINE

    LDY      #$00
    LDX      #$08

.loop:
    CMP      SEPARATORS_TABLE,Y
    BEQ      separator_found
    INY
    DEX
    BNE      .loop

separator_not_found:
    CLC
    RTS

separator_found:
    SEC
    RTS

is_dict_separator:
    SUBROUTINE

    PHA
    JSR      get_dictionary_addr
    LDY      #$00
    LDA      (SCRATCH2),Y
    TAX
    PLA

.loop:
    BEQ      separator_not_found
    INY
    CMP      (SCRATCH2),Y
    BEQ      separator_found
    DEX
    JMP      .loop
get_dictionary_addr:
    SUBROUTINE

    LDY      #HEADER_DICT_ADDR
    LDA      (Z_HEADER_ADDR),Y
    STA      SCRATCH2+1
    INY
    LDA      (Z_HEADER_ADDR),Y
    STA      SCRATCH2
    ADDW     SCRATCH2, Z_HEADER_ADDR, SCRATCH2
    RTS
match_dictionary_word:
    SUBROUTINE

    JSR      get_dictionary_addr
    LDY      #$00                   ; number of dict separators
    LDA      (SCRATCH2),Y
    TAY                             ; skip past and get entry length
    INY
    LDA      (SCRATCH2),Y
    ASL                             ; search_size = entry length x 16
    ASL
    ASL
    ASL
    STA      SCRATCH3
    INY                             ; entry_index = num dict entries
    LDA      (SCRATCH2),Y
    STA      SCRATCH1+1
    INY
    LDA      (SCRATCH2),Y
    STA      SCRATCH1
    INY
    TYA
    ADDA     SCRATCH2               ; entry_addr = start of dictionary entries
    LDY      #$00
    JMP      .try_match
.loop:
    LDA      (SCRATCH2),Y
    CMP      ZCHAR_SCRATCH2+1
    BCS      .possible

.try_match:
    ADDB2    SCRATCH2, SCRATCH3     ; entry_addr += search_size
    SEC                             ; entry_index -= 16
    LDA      SCRATCH1
    SBC      #$10
    STA      SCRATCH1
    BCS      .loop
    DEC      SCRATCH1+1
    BPL      .loop
.possible:
    SUBB2    SCRATCH2, SCRATCH3     ; entry_addr -= search_size
    ADDB2    SCRATCH1, #$10         ; entry_index += 16
    LDA      SCRATCH3               ; search_size /= 16
    LSR
    LSR
    LSR
    LSR
    STA      SCRATCH3
.inner_loop:
    LDY      #$00
    LDA      ZCHAR_SCRATCH2+1
    CMP      (SCRATCH2),Y
    BCC      .not_found
    BNE      .inner_next

    INY
    LDA      ZCHAR_SCRATCH2
    CMP      (SCRATCH2),Y
    BCC      .not_found
    BNE      .inner_next

    LDY      #$02
    LDA      ZCHAR_SCRATCH2+3
    CMP      (SCRATCH2),Y
    BCC      .not_found
    BNE      .inner_next

    INY
    LDA      ZCHAR_SCRATCH2+2
    CMP      (SCRATCH2),Y
    BCC      .not_found
    BEQ      .found

.inner_next:
    ADDB2    SCRATCH2, SCRATCH3     ; entry_addr += search_size
    SUBB     SCRATCH1, #$01         ; --entry_index
    LDA      SCRATCH1
    ORA      SCRATCH1+1
    BNE      .inner_loop
.not_found:
    LDA      #$00
    STA      SCRATCH1+1
    STA      SCRATCH1
    RTS
.found:
    SUBW     SCRATCH2, Z_HEADER_ADDR, SCRATCH1
    RTS
instr_print_char:
    SUBROUTINE

    LDA      OPERAND0
    JSR      buffer_char
    JMP      do_instruction
instr_print_num:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH2
    JSR      print_number
    JMP      do_instruction
print_number:
    SUBROUTINE

    LDA      SCRATCH2+1
    BPL      .print_positive
    JSR      print_negative_num

.print_positive:
    STOB     #$00, SCRATCH3

.loop:
    LDA      SCRATCH2+1
    ORA      SCRATCH2
    BEQ      .is_zero
    STOW     #$000A, SCRATCH1
    JSR      divu16
    LDA      SCRATCH1
    PHA
    INC      SCRATCH3
    JMP      .loop

.is_zero:
    LDA      SCRATCH3
    BEQ      .print_0

.print_digit:
    PLA
    CLC
    ADC      #$30           ; '0'
    JSR      buffer_char
    DEC      SCRATCH3
    BNE      .print_digit
    RTS

.print_0:
    LDA      #$30           ; '0'
    JMP      buffer_char
print_negative_num:
    SUBROUTINE

    LDA      #$2D           ; '-'
    JSR      buffer_char
    JMP      negate
instr_random:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH1
    JSR      get_random
    JSR      divu16
    MOVW     SCRATCH1, SCRATCH2
    INCW     SCRATCH2
    JMP      store_and_next
instr_push:
    SUBROUTINE

    MOVW     OPERAND0, SCRATCH2
    JSR      push
    JMP      do_instruction
instr_pull:
    SUBROUTINE

    JSR      pop
    LDA      OPERAND0
    JMP      stretch_var_put
mulu16:
    SUBROUTINE

    PSHW     SCRATCH3
    STOW     #$0000, SCRATCH3
    LDX      #$10

.loop:
    LDA      SCRATCH1
    CLC
    AND      #$01
    BEQ      .next_bit
    ADDWC    SCRATCH2, SCRATCH3, SCRATCH3

.next_bit:
    RORW      SCRATCH3
    RORW      SCRATCH1
    DEX
    BNE      .loop

    MOVW     SCRATCH1, SCRATCH2
    MOVW     SCRATCH3, SCRATCH1
    PULW     SCRATCH3
    RTS
divu16:
    SUBROUTINE

    PSHW     SCRATCH3
    MOVW     SCRATCH2, SCRATCH3 ; SCRATCH3 is the dividend
    STOW     #$0000, SCRATCH2   ; SCRATCH2 is the remainder
    LDX      #$11

.loop:
    SEC                     ; carry = "not borrow"
    LDA      SCRATCH2       ; Remainder minus divisor (low byte)
    SBC      SCRATCH1
    TAY
    LDA      SCRATCH2+1
    SBC      SCRATCH1+1
    BCC      .skip          ; Divisor did not fit

    ; At this point carry is set, which will affect
    ; the ROLs below.

    STA      SCRATCH2+1     ; Save remainder
    TYA
    STA      SCRATCH2

.skip:
    ROLW     SCRATCH3       ; Shift carry into divisor/quotient left
    ROLW     SCRATCH2       ; Shift divisor/remainder left
    DEX
    BNE      .loop          ; loop end

    CLC                     ; SCRATCH1 = SCRATCH2 >> 1
    LDA      SCRATCH2+1
    ROR
    STA      SCRATCH1+1
    LDA      SCRATCH2
    ROR
    STA      SCRATCH1           ; remainder
    MOVW     SCRATCH3, SCRATCH2 ; quotient
    PULW     SCRATCH3
    RTS
check_sign:
    SUBROUTINE

    STOB     #$00, SIGN_BIT
    LDA      SCRATCH2+1
    JSR      flip_sign
    LDA      SCRATCH1+1
    JSR      flip_sign
    RTS
set_sign:
    SUBROUTINE

    LDA      SIGN_BIT
    AND      #$01
    BNE      negate
    RTS
negate:
    SUBROUTINE

    SUBWL    #$0000, SCRATCH2, SCRATCH2
    RTS
flip_sign:
    SUBROUTINE

    ORA      #$00
    BMI      .do_negate
    RTS

.do_negate:
    INC      SIGN_BIT
    JMP      negate
attr_ptr_and_mask:
    LDA      OPERAND0           ; SCRATCH2 = get_object_addr<obj_num>
    JSR      get_object_addr
    LDA      OPERAND1           ; if (attr_num >= #$10) {
    CMP      #$10               ;  SCRATCH2 += 2; attr_num -= #$10
    BCC      .continue2         ; }
    SEC
    SBC      #$10
    INCW     SCRATCH2
    INCW     SCRATCH2

.continue2:
    STA      SCRATCH1           ; SCRATCH1 = attr_num
    STOW     #$0001, SCRATCH3
    LDA      #$0F
    SEC
    SBC      SCRATCH1
    TAX

.shift_loop:
    BEQ      .done_shift
    ASL      SCRATCH3
    ROL      SCRATCH3+1
    DEX
    JMP      .shift_loop

.done_shift:
    LDY      #$00
    LDA      (SCRATCH2),Y
    STA      SCRATCH1+1
    INY
    LDA      (SCRATCH2),Y
    STA      SCRATCH1
    RTS
get_property_ptr:
    SUBROUTINE

    LDA      OPERAND0
    JSR      get_object_addr
    LDY      #OBJECT_PROPS_OFFSET
    LDA      (SCRATCH2),Y
    STA      SCRATCH1+1
    INY
    LDA      (SCRATCH2),Y
    STA      SCRATCH1
    ADDW     SCRATCH1, Z_HEADER_ADDR, SCRATCH2
    LDY      #$00
    LDA      (SCRATCH2),Y
    ASL
    TAY
    INY
    RTS
get_property_num:
    SUBROUTINE

    LDA      (SCRATCH2),Y
    AND      #$1F
    RTS
get_property_len:
    SUBROUTINE

    LDA      (SCRATCH2),Y
    ROR
    ROR
    ROR
    ROR
    ROR
    AND      #$07
    RTS
next_property:
    SUBROUTINE

    JSR      get_property_len
    TAX

.loop:
    INY
    DEX
    BPL      .loop
    INY
    RTS
get_object_addr:
    SUBROUTINE

    STA      SCRATCH2
    STOB     #$00, SCRATCH2+1
    LDA      SCRATCH2
    ASL      SCRATCH2
    ROL      SCRATCH2+1
    ASL      SCRATCH2
    ROL      SCRATCH2+1
    ASL      SCRATCH2
    ROL      SCRATCH2+1
    CLC
    ADC      SCRATCH2
    BCC      .continue
    INC      SCRATCH2+1
    CLC
.continue:
    ADC      #FIRST_OBJECT_OFFSET
    STA      SCRATCH2
    BCC      .continue2
    INC      SCRATCH2+1
.continue2:
    LDY      #HEADER_OBJECT_TABLE_ADDR+1
    LDA      (Z_HEADER_ADDR),Y
    CLC
    ADC      SCRATCH2
    STA      SCRATCH2
    DEY
    LDA      (Z_HEADER_ADDR),Y
    ADC      SCRATCH2+1
    ADC      Z_HEADER_ADDR+1
    STA      SCRATCH2+1
    RTS
cmp16:
    SUBROUTINE

    LDA      SCRATCH1+1
    EOR      SCRATCH2+1
    BPL      cmpu16
    LDA      SCRATCH1+1
    CMP      SCRATCH2+1
    RTS
cmpu16:
    SUBROUTINE

    LDA      SCRATCH2+1
    CMP      SCRATCH1+1
    BNE      .end
    LDA      SCRATCH2
    CMP      SCRATCH1
.end:
    RTS
push:
    SUBROUTINE

    SUBB     Z_SP, #$01
    LDY      #$00
    LDA      SCRATCH2
    STA      (Z_SP),Y
    SUBB     Z_SP, #$01
    LDA      SCRATCH2+1
    STA      (Z_SP),Y
    INC      STACK_COUNT
    LDA      STACK_COUNT
    CMP      #$B4
    BCC      .end
    JSR      brk

.end:
    RTS
pop:
    SUBROUTINE

    LDY      #$00
    LDA      (Z_SP),Y
    STA      SCRATCH2+1
    INCW     Z_SP
    LDA      (Z_SP),Y
    STA      SCRATCH2
    INCW     Z_SP
    DEC      STACK_COUNT
    BNE      .end
    JSR      brk
.end:
    RTS
get_next_code_byte:
    SUBROUTINE

    LDA      ZCODE_PAGE_VALID
    BEQ      .zcode_page_invalid
    LDY      Z_PC                       ; load from memory
    LDA      (ZCODE_PAGE_ADDR),Y
    INY
    STY      Z_PC
    BEQ      .invalidate_zcode_page     ; will next byte be in next page?
    RTS

.invalidate_zcode_page:
    LDY      #$00
    STY      ZCODE_PAGE_VALID
    INCW     Z_PC+1
    RTS
.zcode_page_invalid:
    LDA      Z_PC+2
    BNE      .find_pc_page_in_page_table
    LDA      Z_PC+1
    CMP      NUM_IMAGE_PAGES
    BCC      .set_page_addr     ; Z_PC is in dynamic or static memory

.find_pc_page_in_page_table:
    MOVW     Z_PC+1, SCRATCH2
    JSR      find_index_of_page_table
    STA      PAGE_TABLE_INDEX
    BCS      .not_found_in_page_table   ; not loaded from disk yet

.set_page_first:
    JSR      set_page_first     ; move page to head of list
    CLC
    LDA      PAGE_TABLE_INDEX
    ADC      NUM_IMAGE_PAGES

.set_page_addr:
    CLC
    ADC      Z_HEADER_ADDR+1
    STA      ZCODE_PAGE_ADDR+1
    STOB     #$00, ZCODE_PAGE_ADDR
    STOB     #$FF, ZCODE_PAGE_VALID ; code page is now valid
    JMP      get_next_code_byte
.not_found_in_page_table:
    CMP      PAGE_TABLE_INDEX2
    BNE      .read_from_disk
    STOB     #$00, ZCODE_PAGE_VALID2

.read_from_disk:
    MOVW     HIGH_MEM_ADDR, SCRATCH2
    LDA      PAGE_TABLE_INDEX
    CLC
    ADC      SCRATCH2+1
    STA      SCRATCH2+1
    MOVW     Z_PC+1, SCRATCH1
    JSR      read_from_sector
    BCC      .good_read
    JMP      main

.good_read:
    LDY      PAGE_TABLE_INDEX
    LDA      Z_PC+1
    STA      (PAGE_L_TABLE),Y
    LDA      Z_PC+2
    STA      (PAGE_H_TABLE),Y
    TYA
    JMP      .set_page_first
load_address:
    SUBROUTINE

    MOVB     SCRATCH2, Z_PC2_L
    MOVB     SCRATCH2+1, Z_PC2_H
    STOB     #$00, Z_PC2_HH
invalidate_zcode_page2:
    SUBROUTINE

    STOB     #$00, ZCODE_PAGE_VALID2
    RTS

load_packed_address:
    SUBROUTINE

    LDA      SCRATCH2
    ASL
    STA      Z_PC2_L
    LDA      SCRATCH2+1
    ROL
    STA      Z_PC2_H
    LDA      #$00
    ROL
    STA      Z_PC2_HH
    JMP      invalidate_zcode_page2
get_next_code_word:
    SUBROUTINE

    JSR      get_next_code_byte2
    PHA
    JSR      get_next_code_byte2
    STA      SCRATCH2
    PLA
    STA      SCRATCH2+1
    RTS
get_next_code_byte2:
    SUBROUTINE

    LDA      ZCODE_PAGE_VALID2
    BEQ      .zcode_page_invalid
    LDY      Z_PC2_L
    LDA      (ZCODE_PAGE_ADDR2),Y
    INY
    STY      Z_PC2_L
    BEQ      .invalidate_zcode_page
    RTS

.invalidate_zcode_page:
    LDY      #$00
    STY      ZCODE_PAGE_VALID2
    INC      Z_PC2_H
    BNE      .end
    INC      Z_PC2_HH

.end:
    RTS

.zcode_page_invalid:
    LDA      Z_PC2_HH
    BNE      .find_pc_page_in_page_table
    LDA      Z_PC2_H
    CMP      NUM_IMAGE_PAGES
    BCC      .set_page_addr

.find_pc_page_in_page_table:
    MOVW     Z_PC2_H, SCRATCH2
    JSR      find_index_of_page_table
    STA      PAGE_TABLE_INDEX2
    BCS      .not_found_in_page_table

.set_page_first:
    JSR      set_page_first
    CLC
    LDA      PAGE_TABLE_INDEX2
    ADC      NUM_IMAGE_PAGES

.set_page_addr:
    CLC
    ADC      Z_HEADER_ADDR+1
    STA      ZCODE_PAGE_ADDR2+1
    STOB     #$00, ZCODE_PAGE_ADDR2
    STOB     #$FF, ZCODE_PAGE_VALID2
    JMP      get_next_code_byte2

.not_found_in_page_table:
    CMP      PAGE_TABLE_INDEX
    BNE      .read_from_disk
    STOB     #$00, ZCODE_PAGE_VALID

.read_from_disk:
    MOVW     HIGH_MEM_ADDR, SCRATCH2
    LDA      PAGE_TABLE_INDEX2
    CLC
    ADC      SCRATCH2+1
    STA      SCRATCH2+1
    MOVW     Z_PC2_H, SCRATCH1
    JSR      read_from_sector
    BCC      .good_read
    JMP      main

.good_read:
    LDY      PAGE_TABLE_INDEX2
    LDA      Z_PC2_H
    STA      (PAGE_L_TABLE),Y
    LDA      Z_PC2_HH
    STA      (PAGE_H_TABLE),Y
    TYA
    JMP      .set_page_first
set_page_first:
    SUBROUTINE

    CMP      FIRST_Z_PAGE
    BEQ      .end
    LDX      FIRST_Z_PAGE           ; prev_first = FIRST_Z_PAGE
    STA      FIRST_Z_PAGE           ; FIRST_Z_PAGE = A

    TAY                             ; SCRATCH2L = NEXT_PAGE_TABLE[FIRST_Z_PAGE]
    LDA      (NEXT_PAGE_TABLE),Y
    STA      SCRATCH2
    TXA                             ; NEXT_PAGE_TABLE[FIRST_Z_PAGE] = prev_first
    STA      (NEXT_PAGE_TABLE),Y

    LDA      (PREV_PAGE_TABLE),Y    ; SCRATCH2H = PREV_PAGE_TABLE[FIRST_Z_PAGE]
    STA      SCRATCH2+1
    LDA      #$FF                   ; PREV_PAGE_TABLE[FIRST_Z_PAGE] = #$FF
    STA      (PREV_PAGE_TABLE),Y
    LDY      SCRATCH2+1
    LDA      SCRATCH2
    STA      (NEXT_PAGE_TABLE),Y    ; NEXT_PAGE_TABLE[SCRATCH2H] = SCRATCH2L
    TXA
    TAY
    LDA      FIRST_Z_PAGE
    STA      (PREV_PAGE_TABLE),Y    ; PREV_PAGE_TABLE[prev_first] = FIRST_Z_PAGE
    LDA      SCRATCH2
    CMP      #$FF
    BEQ      .set_last_z_page
    TAY
    LDA      SCRATCH2+1
    STA      (PREV_PAGE_TABLE),Y    ; PREV_PAGE_TABLE[SCRATCH2L] = SCRATCH2H

.end:
    RTS

.set_last_z_page:
    MOVB     SCRATCH2+1, LAST_Z_PAGE   ; LAST_Z_PAGE = SCRATCH2H
    RTS
find_index_of_page_table:
    SUBROUTINE

    LDX      NUM_PAGE_TABLE_ENTRIES
    LDY      #$00
    LDA      SCRATCH2

.loop:
    CMP      (PAGE_L_TABLE),Y
    BNE      .next
    LDA      SCRATCH2+1
    CMP      (PAGE_H_TABLE),Y
    BEQ      .found
    LDA      SCRATCH2

.next:
    INY
    DEX
    BNE      .loop
    LDA      LAST_Z_PAGE
    SEC
    RTS

.found:
    TYA
    CLC
    RTS
print_zstring:
    SUBROUTINE

    LDA      #$00
    STA      LOCKED_ALPHABET
    STA      ZDECOMPRESS_STATE
    STOB     #$FF, SHIFT_ALPHABET
.loop:
    JSR      get_next_zchar
    BCC      .not_end
    RTS

.not_end:
    STA      SCRATCH3
    BEQ      .space                 ; z-char 0?
    CMP      #$01
    BEQ      .abbreviation          ; z-char 1?
    CMP      #$04
    BCC      .shift_alphabet        ; z-char 2 or 3?
    CMP      #$06
    BCC      .shift_lock_alphabet   ; z-char 4 or 5?
    JSR      get_alphabet

    ; fall through to print the z-character
    ORA      #$00
    BNE      .check_for_alphabet_A1
    LDA      #$5B

.add_ascii_offset:
    CLC
    ADC      SCRATCH3

.printchar:
    JSR      buffer_char
    JMP      .loop
.check_for_alphabet_A1:
    CMP      #$01
    BNE      .map_ascii_for_A2
    LDA      #$3B
    JMP      .add_ascii_offset
.map_ascii_for_A2:
    LDA      SCRATCH3
    SEC
    SBC      #$07
    BCC      .z10bits
    BEQ      .crlf
    TAY
    DEY
    LDA      a2_table,Y
    JMP      .printchar
.z10bits:
    JSR      get_next_zchar
    ASL
    ASL
    ASL
    ASL
    ASL
    PHA
    JSR      get_next_zchar
    STA      SCRATCH3
    PLA
    ORA      SCRATCH3
    JMP      .printchar
.space:
    LDA      #$20
    JMP      .printchar
.crlf:
    LDA      #$0D
    JSR      buffer_char
    LDA      #$0A
    JMP      .printchar
.shift_alphabet:
    JSR      get_alphabet
    CLC
    ADC      #$02
    ADC      SCRATCH3
    JSR      A_mod_3
    STA      SHIFT_ALPHABET
    JMP      .loop

.shift_lock_alphabet:
    JSR      get_alphabet
    CLC
    ADC      SCRATCH3
    JSR      A_mod_3
    STA      LOCKED_ALPHABET
    JMP      .loop
.abbreviation:
    JSR      get_next_zchar
    ASL
    ADC      #$01
    TAY
    LDA      (Z_ABBREV_TABLE),Y
    STA      SCRATCH2
    DEY
    LDA      (Z_ABBREV_TABLE),Y
    STA      SCRATCH2+1

    ; Save the decompress state

    LDA      LOCKED_ALPHABET
    PHA
    LDA      ZDECOMPRESS_STATE
    PHA
    LDA      ZCHARS_L
    PHA
    LDA      ZCHARS_H
    PHA
    LDA      Z_PC2_L
    PHA
    LDA      Z_PC2_H
    PHA
    LDA      Z_PC2_HH
    PHA

    JSR      load_packed_address
    JSR      print_zstring

    ; Restore the decompress state

    PLA
    STA      Z_PC2_HH
    PLA
    STA      Z_PC2_H
    PLA
    STA      Z_PC2_L
    LDA      #$00
    STA      ZCODE_PAGE_VALID2
    PLA
    STA      ZCHARS_H
    PLA
    STA      ZCHARS_L
    PLA
    STA      ZDECOMPRESS_STATE
    PLA
    STA      LOCKED_ALPHABET
    STOB     #$FF, SHIFT_ALPHABET ; Resets any temporary shift
    JMP      .loop
A_mod_3:
    CMP      #$03
    BCC      .end
    SEC
    SBC      #$03
    JMP      A_mod_3

.end:
    RTS
a2_table:
    DC       "0123456789.,!?_#'"
    DC       '"
    DC       "/\-:()"
get_alphabet:
    LDA      SHIFT_ALPHABET
    BPL      .remove_shift
    LDA      LOCKED_ALPHABET
    RTS

.remove_shift:
    LDY      #$FF
    STY      SHIFT_ALPHABET
    RTS
get_next_zchar:
    LDA      ZDECOMPRESS_STATE
    BPL      .check_for_char_1
    SEC
    RTS

.check_for_char_1:
    BNE      .check_for_char_2
    INC      ZDECOMPRESS_STATE
    JSR      get_next_code_word
    MOVW     SCRATCH2, ZCHARS_L
    LDA      ZCHARS_H
    LSR
    LSR
    AND      #$1F
    CLC
    RTS

.check_for_char_2:
    SEC
    SBC      #$01
    BNE      .check_for_last
    STOB     #$02, ZDECOMPRESS_STATE
    LDA      ZCHARS_H
    LSR
    LDA      ZCHARS_L
    ROR
    TAY
    LDA      ZCHARS_H
    LSR
    LSR
    TYA
    ROR
    LSR
    LSR
    LSR
    AND      #$1F
    CLC
    RTS

.check_for_last:
    STOB     #$00, ZDECOMPRESS_STATE
    LDA      ZCHARS_H
    BPL      .get_char_3
    STOB     #$FF, ZDECOMPRESS_STATE

.get_char_3:
    LDA      ZCHARS_L
    AND      #$1F
    CLC
    RTS
ascii_to_zchar:
    SUBROUTINE

    STOB     #$00, LOCKED_ALPHABET
    LDX      #$00
    LDY      #$06

.clear:
    LDA      #$05
    STA      ZCHAR_SCRATCH2,X
    INX
    DEY
    BNE      .clear

    STOB     #$06, SCRATCH3+1   ; nchars = 6
    LDA      #$00
    STA      SCRATCH1           ; dest_index = 0
    STA      SCRATCH2           ; index = 0
.loop:
    LDX      SCRATCH2           ; c = ZCHAR_SCRATCH1[index++]
    INC      SCRATCH2
    LDA      ZCHAR_SCRATCH1,X
    STA      SCRATCH3
    BNE      .continue
    LDA      #$05
    JMP      .store_zchar
.continue:
    LDA      SCRATCH1           ; save dest_index
    PHA
    LDA      SCRATCH3           ; alphabet = get_alphabet_for_char(c)
    JSR      get_alphabet_for_char
    STA      SCRATCH1
    CMP      LOCKED_ALPHABET
    BEQ      .same_alphabet
    LDX      SCRATCH2
    LDA      ZCHAR_SCRATCH1,X
    JSR      get_alphabet_for_char
    CMP      SCRATCH1
    BNE      .shift_alphabet
    SEC                         ; shift_char = shift lock char (4 or 5)
    SBC      LOCKED_ALPHABET
    CLC
    ADC      #$03
    JSR      A_mod_3
    CLC
    ADC      #$03
    STA      SCRATCH1+1
    MOVB     SCRATCH1, LOCKED_ALPHABET  ; LOCKED_ALPHABET = alphabet
    PLA                         ; restore dest_index
    STA      SCRATCH1
    LDA      SCRATCH1+1         ; ZCHAR_SCRATCH2[dest_index] = shift_char
    LDX      SCRATCH1
    STA      ZCHAR_SCRATCH2,X
    INC      SCRATCH1           ; ++dest_index
    DEC      SCRATCH3+1         ; --nchars
    BNE      .add_shifted_char
    JMP      z_compress

.add_shifted_char:
    LDA      SCRATCH1           ; save dest_index
    PHA
    JMP      .same_alphabet
.shift_alphabet:
    LDA      SCRATCH1           ; shift_char = shift char (2 or 3)
    SEC
    SBC      LOCKED_ALPHABET
    CLC
    ADC      #$03
    JSR      A_mod_3
    TAX
    INX
    PLA
    STA      SCRATCH1           ; restore dest_index
    TXA                         ; ZCHAR_SCRATCH2[dest_index] = shift_char
    LDX      SCRATCH1
    STA      ZCHAR_SCRATCH2,X
    INC      SCRATCH1           ; ++dest_index
    DEC      SCRATCH3+1         ; --nchars
    BNE      .save_dest_index_and_same_alphabet

stretchy_z_compress:
    JMP      z_compress
.save_dest_index_and_same_alphabet:
    LDA      SCRATCH1           ; save dest_index
    PHA

.same_alphabet:
    PLA
    STA      SCRATCH1           ; restore dest_index
    LDA      SCRATCH3
    JSR      get_alphabet_for_char
    SEC
    SBC      #$01               ; alphabet_minus_1 = case(c) - 1
    BPL      .not_lowercase
    LDA      SCRATCH3
    SEC
    SBC      #$5B               ; c -= 'a'-6
.store_zchar:
    LDX      SCRATCH1           ; ZCHAR_SCRATCH2[dest_index] = c
    STA      ZCHAR_SCRATCH2,X
    INC      SCRATCH1           ; ++dest_index
    DEC      SCRATCH3+1         ; --nchars
    BEQ      .dest_full
    JMP      .loop

.dest_full:
    JMP      z_compress
.not_lowercase:
    BNE      .not_alphabetic
    LDA      SCRATCH3
    SEC
    SBC      #$3B               ; c -= 'A'-6
    JMP      .store_zchar
.not_alphabetic:
    LDA      SCRATCH3
    JSR      search_nonalpha_table
    BNE      .store_zchar
    LDA      #$06               ; ZCHAR_SCRATCH2[dest_index] = 6
    LDX      SCRATCH1
    STA      ZCHAR_SCRATCH2,X
    INC      SCRATCH1           ; ++dest_index
    DEC      SCRATCH3+1         ; --nchars
    BEQ      z_compress

    LDA      SCRATCH3           ; ZCHAR_SCRATCH2[dest_index] = c >> 5
    LSR
    LSR
    LSR
    LSR
    LSR
    AND      #$03
    LDX      SCRATCH1
    STA      ZCHAR_SCRATCH2,X
    INC      SCRATCH1           ; ++dest_index
    DEC      SCRATCH3+1         ; --nchars
    BEQ      z_compress

    LDA      SCRATCH3           ; c &= 0x1F
    AND      #$1F
    JMP      .store_zchar
search_nonalpha_table:
    SUBROUTINE

    LDX      #$24

.loop:
    CMP      a2_table,X
    BEQ      .found
    DEX
    BPL      .loop
    LDY      #$00
    RTS

.found:
    TXA
    CLC
    ADC      #$08
    RTS
get_alphabet_for_char:
    SUBROUTINE

    CMP      #$61
    BCC      .check_upper
    CMP      #$7B
    BCS      .check_upper
    LDA      #$00
    RTS

.check_upper:
    CMP      #$41
    BCC      .check_nonletter
    CMP      #$5B
    BCS      .check_nonletter
    LDA      #$01
    RTS

.check_nonletter:
    ORA      #$00
    BEQ      .return
    BMI      .return
    LDA      #$02

.return:
    RTS
z_compress:
    SUBROUTINE

    LDA      ZCHAR_SCRATCH2+1
    ASL
    ASL
    ASL
    ASL
    ROL      ZCHAR_SCRATCH2
    ASL
    ROL      ZCHAR_SCRATCH2
    LDX      ZCHAR_SCRATCH2
    STX      ZCHAR_SCRATCH2+1
    ORA      ZCHAR_SCRATCH2+2
    STA      ZCHAR_SCRATCH2
    LDA      ZCHAR_SCRATCH2+4
    ASL
    ASL
    ASL
    ASL
    ROL      ZCHAR_SCRATCH2+3
    ASL
    ROL      ZCHAR_SCRATCH2+3
    LDX      ZCHAR_SCRATCH2+3
    STX      ZCHAR_SCRATCH2+3
    ORA      ZCHAR_SCRATCH2+5
    STA      ZCHAR_SCRATCH2+2
    LDA      ZCHAR_SCRATCH2+3
    ORA      #$80
    STA      ZCHAR_SCRATCH2+3
    RTS
instr_restart:
    SUBROUTINE

    JSR      dump_buffer_with_more
    JMP      main
locate_last_ram_page:
    SUBROUTINE

    MOVB     #$C0, SCRATCH2+1
    MOVB     #$FF, SCRATCH2
    LDY      #$00

.loop:
    DEC      SCRATCH2+1
    LDA      (SCRATCH2),Y
    CMP      (SCRATCH2),Y
    BNE      .loop
    EOR      #$FF
    STA      (SCRATCH2),Y
    CMP      (SCRATCH2),Y
    BNE      .loop
    EOR      #$FF
    STA      (SCRATCH2),Y
    LDA      SCRATCH2+1
    RTS
buffer_char:
    SUBROUTINE

    LDX      BUFF_END
    CMP      #$0D
    BNE      .not_0D
    JMP      dump_buffer_with_more

.not_0D:
    CMP      #$20
    BCC      buffer_char_set_buffer_end
    CMP      #$60
    BCC      .store_char
    CMP      #$80
    BCS      .store_char
    SEC
    SBC      #$20              ; converts to uppercase

.store_char:
    ORA      #$80              ; sets as normal text
    STA      BUFF_AREA,X
    CPX      WNDWDTH
    BCS      .hit_right_limit
    INX

buffer_char_set_buffer_end:
    STX      BUFF_END
    RTS

.hit_right_limit:
    LDA      #$A0  ; normal space

.loop:
    CMP      BUFF_AREA,X
    BEQ      .endloop
    DEX
    BNE      .loop
    LDX      WNDWDTH

.endloop:
    STX      BUFF_LINE_LEN
    STX      BUFF_END
    JSR      dump_buffer_with_more
.increment_length:
    INC      BUFF_LINE_LEN
    LDX      BUFF_LINE_LEN
    CPX      WNDWDTH
    BCC      .move_last_char
    BEQ      .move_last_char
    RTS

.move_last_char:
    LDA      BUFF_AREA,X
    LDX      BUFF_END
    STA      BUFF_AREA,X
    INC      BUFF_END
    LDX      BUFF_LINE_LEN
    JMP      .increment_length
dump_buffer_line:
    SUBROUTINE

    LDY      #HEADER_FLAGS2+1
    LDA      (Z_HEADER_ADDR),Y
    AND      #$01
    BEQ      .skip_printer
    JSR      dump_buffer_to_printer

.skip_printer:
    JSR      dump_buffer_to_screen
    RTS
printer_card_initialized_flag:
    BYTE     00

dump_buffer_to_printer:
    SUBROUTINE

    PSHW     CSW
    MOVW     PRINTER_CSW, CSW
    LDX      #$00
    LDA      printer_card_initialized_flag
    BNE      .loop
    INC      printer_card_initialized_flag

.printer_set_80_column_output:
    LDA      #$09      ; ctrl-I
    JSR      COUT
    STOB     #$91, $0779      ; 'Q' into scratchpad RAM for slot 1.
    LDA      #$B8      ; '8'
    JSR      COUT
    LDA      #$B0      ; '0'
    JSR      COUT
    LDA      #$CE      ; 'N'
    JSR      COUT

.loop:
    CPX      BUFF_END
    BEQ      .done
    LDA      BUFF_AREA,X
    JSR      COUT
    INX
    JMP      .loop

.done:
    MOVW     CSW, PRINTER_CSW
    PULW     CSW
    RTS
dump_buffer_to_screen:
    SUBROUTINE

    LDX      #$00

.loop:
    CPX      BUFF_END
    BEQ      .done
    LDA      BUFF_AREA,X
    JSR      COUT1
    INX
    JMP      .loop

.done:
    LDX      #$00
    STX      BUFF_END
    RTS
string_more:
    DC       "[MORE]"

dump_buffer_with_more:
    SUBROUTINE

    INC      CURR_LINE
    LDA      CURR_LINE
    CMP      WNDBTM
    BCC      .good_to_go    ; haven't reached bottom of screen yet

    STOW     string_more, SCRATCH2
    LDX      #6

    STOB     #$3F, INVFLG
    JSR      cout_string    ; print [MORE] in inverse text
    STOB     #$FF, INVFLG

    JSR      RDKEY          ; wait for keypress
    LDA      CH
    SEC
    SBC      #$06
    STA      CH             ; move cursor back 6
    JSR      CLREOL         ; and clear the line
    MOVB     WNDTOP, CURR_LINE
    INC      CURR_LINE      ; start at top of screen

.good_to_go:
    LDA      BUFF_END
    PHA
    JSR      dump_buffer_line
    PLA
    CMP      WNDWDTH
    BEQ      .skip_newline
    LDA      #$8D
    JSR      COUT1

.skip_newline:
    LDY      #HEADER_FLAGS2+1
    LDA      (Z_HEADER_ADDR),Y
    AND      #$01
    BEQ      .reset_buffer_end

    PSHW     CSW
    MOVW     PRINTER_CSW, CSW

    LDA      #$8D
    JSR      COUT

    MOVW     CSW, PRINTER_CSW
    PULW     CSW

.reset_buffer_end:
    LDX      #$00
    JMP      buffer_char_set_buffer_end
home:
    SUBROUTINE

    JSR      HOME
    MOVB     WNDTOP, CURR_LINE
    RTS
sScore:
    DC       "SCORE:"

print_status_line:
    SUBROUTINE

    JSR      dump_buffer_line
    LDA      CH
    PHA
    LDA      CV
    PHA
    LDA      #$00
    STA      CH
    STA      CV
    JSR      VTAB
    STOB     #$3F, INVFLG
    JSR      CLREOL

    LDA      #VAR_CURR_ROOM
    JSR      var_get
    JSR      print_obj_in_A
    JSR      dump_buffer_to_screen

    STOB     #25, CH
    STOW     #sScore, SCRATCH2
    LDX      #$06
    JSR      cout_string

    INC      CH
    LDA      #VAR_SCORE
    JSR      var_get
    JSR      print_number

    LDA      #'/
    JSR      buffer_char

    LDA      #VAR_MAX_SCORE
    JSR      var_get
    JSR      print_number
    JSR      dump_buffer_to_screen

    STOB     #$FF, INVFLG
    PLA
    STA      CV
    PLA
    STA      CH
    JSR      VTAB
    RTS
cout_string:
    SUBROUTINE

    LDY      #$00

.loop:
    LDA      (SCRATCH2),Y
    ORA      #$80
    JSR      COUT1
    INY
    DEX
    BNE      .loop
    RTS
read_line:
    SUBROUTINE

    JSR      dump_buffer_line
    MOVB     WNDTOP, CURR_LINE
    JSR      GETLN1
    INC      CURR_LINE
    LDA      #$8D               ; newline
    STA      BUFF_AREA,X
    INX                         ; X = num of chars in input
    TXA
    PHA                         ; save X
    LDY      #HEADER_FLAGS2+1
    LDA      (Z_HEADER_ADDR),Y
    AND      #$01               ; Mask for transcript on
    BEQ      .continue
    TXA
    STA      BUFF_END
    JSR      dump_buffer_to_printer
    STOB     #$00, BUFF_END

.continue
    PLA                         ; restore num of chars in input
    LDY      #$00               ; truncate to max num of chars
    CMP      (OPERAND0),Y
    BCC      .continue2
    LDA      (OPERAND0),Y

.continue2:
    PHA                         ; save num of chars
    BEQ      .end
    TAX

.loop:
    LDA      BUFF_AREA,Y   ; convert A-Z to lowercase
    AND      #$7F
    CMP      #$41
    BCC      .continue3
    CMP      #$5B
    BCS      .continue3
    ORA      #$20

.continue3:
    INY
    STA      (OPERAND0),Y
    CMP      #$0D
    BEQ      .end
    DEX
    BNE      .loop

.end:
    PLA                         ; restore num of chars
    RTS
reset_window:
    SUBROUTINE

    STOB     #1, WNDTOP
    STOB     #0, WNDLFT
    STOB     #40, WNDWDTH
    STOB     #24, WNDBTM
    STOB     #$3E, PROMPT  ; '>'
    STOB     #$FF, INVFLG
    JSR      home
    RTS
iob:
    DC      #$01            ; table_type (must be 1)
iob.slot_times_16:
    DC      #$60            ; slot_times_16
iob.drive:
    DC      #$01            ; drive_number
    DC      #$00            ; volume
iob.track:
    DC      #$00            ; track
iob.sector:
    DC      #$00            ; sector
    DC.W    #dct            ; dct_addr
iob.buffer:
    DC.W    #$0000          ; buffer_addr
    DC      #$00            ; unused
    DC      #$00            ; partial_byte_count
iob.command:
    DC      #$00            ; command
    DC      #$00            ; ret_code
    DC      #$00            ; last_volume
    DC      #$60            ; last_slot_times_16
    DC      #$01            ; last_drive_number

dct:
    DC      #$00            ; device_type (0 for DISK II)
    DC      #$01            ; phases_per_track (1 for DISK II)
dct.motor_count:
    DC.W    #$D8EF          ; motor_on_time_count ($EFD8 for DISK II)
do_rwts_on_sector:
    SUBROUTINE

    STA      iob.command
    MOVW     SCRATCH2, iob.buffer
    STOB     #$03, iob.track
    LDA      SCRATCH1
    LDX      SCRATCH1+1
    SEC

.adjust_track:
    SBC      SECTORS_PER_TRACK
    BCS      .inc_track
    DEX
    BMI      .do_read
    SEC

.inc_track:
    INC      iob.track
    JMP      .adjust_track

.do_read:
    CLC
    ADC      SECTORS_PER_TRACK
    STA      iob.sector
    LDA      #$1D
    LDY      #$AC
    JSR      RWTS
    RTS
read_next_sector:
    SUBROUTINE

    STOW     #BUFF_AREA, SCRATCH2

inc_sector_and_read:
    SUBROUTINE

    INCW     SCRATCH1

read_from_sector:
    SUBROUTINE

    LDA      #$01
    JSR      do_rwts_on_sector
    RTS
write_next_sector:
    SUBROUTINE

    STOW     #BUFF_AREA, SCRATCH2

inc_sector_and_write:
    SUBROUTINE

    INCW     SCRATCH1

.write_next_sector:
    PSHW     dct.motor_count
    STOW2    #$D8EF, dct.motor_count
    LDA      #$02
    JSR      do_rwts_on_sector
    PULW     dct.motor_count
    RTS
do_reset_window:
    JSR      reset_window
    RTS
print_ascii_string:
    SUBROUTINE

    STX      SCRATCH3
    LDY      #$00
    STY      SCRATCH3+1

.loop:
    LDY      SCRATCH3+1
    LDA      (SCRATCH2),Y
    JSR      buffer_char
    INC      SCRATCH3+1
    DEC      SCRATCH3
    BNE      .loop
    RTS
sPleaseInsert:
    DC      "PLEASE INSERT SAVE DISKETTE,"
prompt_offset:
    DC      0
sSlotPrompt:
    DC      "SLOT     (1-7):"
save_slot:
    DC      '6
sDrivePrompt:
    DC      "DRIVE    (1-2):"
save_drive:
    DC      '2
sPositionPrompt:
    DC      "POSITION (0-7):"
save_position:
    DC      '0
sDefault:
    DC      "DEFAULT = "
sReturnToBegin:
    DC      "--- PRESS 'RETURN' KEY TO BEGIN ---"
please_insert_save_diskette:
    SUBROUTINE

    JSR      home
    JSR      dump_buffer_with_more
    JSR      dump_buffer_with_more
    STOW     sPleaseInsert, SCRATCH2
    LDX      #28
    JSR      print_ascii_string
    JSR      dump_buffer_with_more
.get_position_from_user:
    LDA      #(sPositionPrompt-sSlotPrompt)
    STA      prompt_offset
    JSR      get_prompted_number_from_user
    CMP      #'0
    BCC      .get_position_from_user
    CMP      #'8
    BCS      .get_position_from_user
    STA      save_position
    JSR      buffer_char
.get_slot_from_user:
    LDA      #(sSlotPrompt - sSlotPrompt)
    STA      prompt_offset
    JSR      get_prompted_number_from_user
    CMP      #'1
    BCC      .get_slot_from_user
    CMP      #'8
    BCS      .get_slot_from_user
    TAX
    AND      #$07
    ASL
    ASL
    ASL
    ASL
    STA      iob.slot_times_16
    TXA
    STA      save_slot
    JSR      buffer_char
.get_drive_from_user:
    LDA      #(sDrivePrompt - sSlotPrompt)
    STA      prompt_offset
    JSR      get_prompted_number_from_user
    CMP      #'1
    BCC      .get_drive_from_user
    CMP      #'3
    BCS      .get_drive_from_user
    TAX
    AND      #$03
    STA      iob.drive
    TXA
    STA      save_drive
    JSR      buffer_char
.press_return_key_to_begin:
    JSR      dump_buffer_with_more
    STOW     sReturnToBegin, SCRATCH2
    LDX      #35
    JSR      print_ascii_string
    JSR      dump_buffer_line
    JSR      RDKEY
    CMP      #$8D
    BNE      .press_return_key_to_begin
    LDA      #$FF
    STA      SCRATCH1
    STA      SCRATCH1+1
    LDA      save_position
    AND      #$07
    BEQ      .end
    TAY

.loop:
    ADDB     SCRATCH1, #64
    DEY
    BNE      .loop

.end:
    JSR      dump_buffer_with_more
    RTS
get_prompted_number_from_user:
    SUBROUTINE

    JSR      dump_buffer_with_more
    STOW     sSlotPrompt, SCRATCH2      ; print prompt
    ADDB     SCRATCH2, prompt_offset
    LDX      #15
    JSR      print_ascii_string
    JSR      dump_buffer_line
    LDA      #25
    STA      CH
    LDA      #$3F                       ; set inverse
    STA      INVFLG
    STOW     sDefault, SCRATCH2         ; print "DEFAULT = "
    LDX      #10
    JSR      cout_string
    STOW     save_slot, SCRATCH2        ; print default value
    ADDB     SCRATCH2, prompt_offset
    LDX      #1
    JSR      cout_string
    LDA      #$FF                       ; clear inverse
    STA      INVFLG
    JSR      RDKEY                      ; A = read key
    PHA
    LDA      #25
    STA      CH
    JSR      CLREOL                     ; clear line
    PLA
    CMP      #$8D                       ; newline?
    BNE      .end
    LDY      prompt_offset              ; store result
    LDA      save_slot,Y

.end:
    AND      #$7F
    RTS
sReinsertGameDiskette:
    DC      "PLEASE RE-INSERT GAME DISKETTE,"
sPressReturnToContinue:
    DC      "--- PRESS 'RETURN' KEY TO CONTINUE ---"

please_reinsert_game_diskette:
    SUBROUTINE

    LDA      iob.slot_times_16
    CMP      #$60
    BNE      .set_slot6_drive1
    LDA      iob.drive
    CMP      #$01
    BNE      .set_slot6_drive1
    JSR      dump_buffer_with_more
    STOW     sReinsertGameDiskette, SCRATCH2
    LDX      #31
    JSR      print_ascii_string

.await_return_key:
    JSR      dump_buffer_with_more
    STOW     sPressReturnToContinue, SCRATCH2
    LDX      #38
    JSR      print_ascii_string
    JSR      dump_buffer_line
    JSR      RDKEY
    CMP      #$8D
    BNE      .await_return_key
    JSR      dump_buffer_with_more

.set_slot6_drive1:
    STOB     #$60, iob.slot_times_16
    STOB     #$01, iob.drive
    RTS
instr_save:
    SUBROUTINE

    JSR      please_insert_save_diskette
    LDX      #$00
    LDY      #HEADER_VERSION
    LDA      (Z_HEADER_ADDR),Y
    STA      BUFF_AREA,X
    INX
    STOW     #Z_PC, SCRATCH2
    LDY      #$03
    JSR      copy_data_to_buff
    STOW     #LOCAL_ZVARS, SCRATCH2
    LDY      #30
    JSR      copy_data_to_buff

    STOW     #STACK_COUNT, SCRATCH2
    LDY      #6
    JSR      copy_data_to_buff

    JSR      write_next_sector
    BCS      .fail
    LDX      #$00
    STOW     #$0280, SCRATCH2
    LDY      #$00
    JSR      copy_data_to_buff

    JSR      write_next_sector
    BCS      .fail

    LDX      #$00
    STOW     #$0380, SCRATCH2
    LDY      #$68
    JSR      copy_data_to_buff

    JSR      write_next_sector
    BCS      .fail
    MOVW     Z_HEADER_ADDR, SCRATCH2
    LDY      #HEADER_STATIC_MEM_BASE
    LDA      (Z_HEADER_ADDR),Y
    STA      SCRATCH3                   ; big-endian!
    INC      SCRATCH3

.loop:
    JSR      inc_sector_and_write
    BCS      .fail
    INC      SCRATCH2+1
    DEC      SCRATCH3
    BNE      .loop
    JSR      inc_sector_and_write
    BCS      .fail
    JSR      please_reinsert_game_diskette
    JMP      branch
.fail:
    JSR      please_reinsert_game_diskette
    JMP      negated_branch
copy_data_to_buff:
    SUBROUTINE

    DEY
    LDA      (SCRATCH2),Y
    STA      BUFF_AREA,X
    INX
    CPY      #$00
    BNE      copy_data_to_buff
    RTS
instr_restore:
    SUBROUTINE

    JSR      please_insert_save_diskette
    JSR      read_next_sector
    BCC      .continue
    JMP      .fail

.continue:
    LDX      #$00
    LDY      #HEADER_VERSION
    LDA      (Z_HEADER_ADDR),Y
    CMP      BUFF_AREA,X
    BEQ      .continue2
    JMP      .fail
.continue2:
    LDY      #HEADER_FLAGS2+1
    LDA      (Z_HEADER_ADDR),Y
    STA      SIGN_BIT
    INX
    STOW     #Z_PC, SCRATCH2
    LDY      #3
    JSR      copy_data_from_buff
    LDA      #$00
    STA      ZCODE_PAGE_VALID
    STOW     #LOCAL_ZVARS, SCRATCH2
    LDY      #30
    JSR      copy_data_from_buff
    STOW     #STACK_COUNT, SCRATCH2
    LDY      #6
    JSR      copy_data_from_buff
    JSR      read_next_sector
    BCS      .fail
    LDX      #$00
    STOW     #$0280, SCRATCH2
    LDY      #$00
    JSR      copy_data_from_buff
    JSR      read_next_sector
    BCS      .fail
    LDX      #$00
    STOW     #$0380, SCRATCH2
    LDY      #$68
    JSR      copy_data_from_buff
    MOVW     Z_HEADER_ADDR, SCRATCH2
    LDY      #HEADER_STATIC_MEM_BASE
    LDA      (Z_HEADER_ADDR),Y
    STA      SCRATCH3               ; big-endian!
    INC      SCRATCH3

.loop:
    JSR      inc_sector_and_read
    BCS      .fail
    INC      SCRATCH2+1
    DEC      SCRATCH3
    BNE      .loop
    LDA      SIGN_BIT
    LDY      #HEADER_FLAGS2+1
    STA      (Z_HEADER_ADDR),Y
    JSR      please_reinsert_game_diskette
    JMP      branch
.fail:
    JSR      please_reinsert_game_diskette
    JMP      negated_branch
copy_data_from_buff:
    SUBROUTINE

    DEY
    LDA      BUFF_AREA,X
    STA      (SCRATCH2),Y
    INX
    CPY      #$00
    BNE      copy_data_from_buff
    RTS
sEndOfSession:
    DC       "-- END OF SESSION --"

instr_quit:
    SUBROUTINE

    JSR      dump_buffer_with_more
    STOW     sEndOfSession, SCRATCH2
    LDX      #20
    JSR      print_ascii_string
    JSR      dump_buffer_with_more

.spinloop:
    JMP      .spinloop
sInternalError:
    DC       "ZORK INTERNAL ERROR!"
brk:
    BRK
get_random:
    SUBROUTINE

    ROL      RANDOM_VAL+1
    MOVW     RANDOM_VAL, SCRATCH2
    RTS

    HEX    00 00 00 00 00 00 00 00
    HEX    00 FC 19 00 00