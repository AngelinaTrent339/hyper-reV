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
		push rdi
		mov rdi, rcx        ; dest
		mov rax, rdx        ; val (only low byte used)
		mov rcx, r8         ; count
		rep stosb           ; fill memory
		mov rax, rdi        ; return original dest
		sub rax, r8         ; adjust back to start
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