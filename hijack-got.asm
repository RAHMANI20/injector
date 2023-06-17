BITS 64

SECTION .data
	msg db "Je suis trop un hacker", 10, 0
	msg_len equ $ - msg
	
SECTION .text
global main

main:
    ; save context
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r11
    
    ; write syscall
    mov rdx, msg_len ; length of msg
    lea rsi, [rel msg] ; message to display 
    mov rdi, 1 ; stdout 
    mov rax, 1 ; syscall number for write
    syscall ; invoke syscall
    
    ;load context
    pop r11
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    
    ; return
    ret


