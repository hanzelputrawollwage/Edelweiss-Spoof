#!/bin/bash
echo "[*] Building Edelweiss..." 
nasm -f elf64 edelweiss.asm -o edelweiss.o && ld edelweiss.o -o edelweiss
echo "[+] Done. Run with: sudo ./edelweiss"