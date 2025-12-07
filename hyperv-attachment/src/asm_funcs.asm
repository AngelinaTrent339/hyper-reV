.CODE
	cli_func PROC
		cli
		ret
	cli_func ENDP
	sti_func PROC
		sti
		ret
	sti_func ENDP
	clgi_func PROC
		clgi
		ret
	clgi_func ENDP
	stgi_func PROC
		stgi
		ret
	stgi_func ENDP

; memset implementation for /NODEFAULTLIB builds
; void* memset(void* dest, int val, size_t count)
; RCX = dest, RDX = val, R8 = count
; Returns dest in RAX
	memset PROC
		mov r9, rcx         ; save original dest in r9 (non-volatile scratch)
		push rdi
		mov rdi, rcx        ; dest for stosb
		mov rax, rdx        ; val (only AL is used by stosb)
		mov rcx, r8         ; count for rep
		rep stosb           ; fill memory (modifies RDI, RCX)
		mov rax, r9         ; return original dest
		pop rdi
		ret
	memset ENDP

; __chkstk - stack probe for large stack allocations
; RAX = number of bytes to allocate
; This is a no-op for kernel mode with preallocated stacks
	__chkstk PROC
		ret
	__chkstk ENDP

END