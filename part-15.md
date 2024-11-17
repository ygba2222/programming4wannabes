Finally we are going to get our crypter complete and operational. We have already covered the main technical areas involving ohow ton crypt binaries and now we just need to commit. We already have a complete crypter able to crypt the relevant parts of the code and inject our stub using different techniques. We are only missing the final version of our stub.

In this last instalment we are going to put together all the elements to get our stub complete.

What does that stub do again?
Before continuing, let’s recall what the stub does:

Change permissions of the memory blocks we want to decrypt
Decrypt memory
Restore permissions
Give control to the Original Entry Point
That is it. Actually it is pretty straightforward, so let’s code that stub. But before we need to do some small changes in the crypter, and prepare the assembly code for the stub.

The stub skeleton
We could write our stub such as it will look for the .text and .rodata sections and decrypt them, but, as this information is already needed by the crypter, and the crypter is going to inject the stub and patch it anyway, we better also add the pointers and size of the memory blocks to encode from the C code. This is easier and also will make our stub smaller.

stub_start:
	;; Let's create a stack frame 
	push rbp
	mov  rbp, rsp
	;; Save registerrs
	push rdi
	push rsi
	push rdx
	push rax
	
	;; Patch return address
	sub QWORD [rbp + 0x8], 5
	mov rax, [rbp + 0x8]
	;; Restore original instructions
patch1:	
	mov rdx, 0x1122334455667788
	mov QWORD [rax], rdx
	
	;; Change memory permissions
	;; Decrypt
        mov rax, 1    ; SYS_write = 1
        mov rdi, 1    ; fd = 1
        lea rsi, [rel msg]  ; buf = msg
        mov rdx, 13   ; count = 13 (the number of bytes to write)
        syscall  ;
	;; Restore memory permissions
		

	pop rax	
	pop rdx
	pop rsi
	pop rdi
	pop rbp
	ret
	

;;;  Data
text_ptr:       dq 0
text_size:      dw 0
rodata_ptr:     dq 0
rodata_size:    dw 0
key:            db "0x00Sec!",0
msg:    db 'Hello World!',0x0a

		
This is basically the stub for the last injection technique described in previous instalment but just including some variables that we will need and a stack frame that will make easier the multiple invocations of the rc4 function to decrypt our program.

Note: Yes, we have move the restoration of original instructions at the beginning of the program. Rational is that we will be adding code in this function and we do not want to update the offset to that instruction with every change.

Also note that, we are restoring the original entry point before decrypting the text segment. This means that the crypter has to patch the stub with the Crypted instructions at the OEP, not the real ones. Or in other words, the crypter will patch the stub after crypting the text segment of the target binary.

In order to simplify the code, we will allocate space for the pointers and size to crypted sections, namely, .text and .rodata. The crypter will need this information to crypt the program anyway, so we will just make it write that data to the stub, during the injection process. This way, our stub doesn’t need to find the relevant sections and can be shorter.

For the rc4 implementation, we can do three things:

Extract the object code from the crypter binary itself… remember we have implemented an rc4 function there.
Re-code the function directly in asm,
Compile our C code and link it with our asm stub.
What should you do?.. Well, it depends, I will show you how to do two of the techniques above. That should give you enough information to be able to implement the last one by yourself. Which one is better?.. There is no one better, it depends on what you need to do… so you better learn all of them :wink: .

Extracting RC4 from C program
As I said, we had implemented an rc4 function on our crypter. It looks like this:

int rc4 (unsigned char *msg, int mlen, unsigned char *key, int klen) {
  int           i,j;
  unsigned char S[256]; // Permutation matrix
  
  // KSA: Key-Schedulling Algorithm
  for (i = 0; i < 255; S[i] = i,i++);
  for (j = 0, i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % klen] ) % 256;
    SWAP(S[i],S[j]);
  }
  // Encoding
  i = j = 0;
  int cnt = 0;
  while (cnt < mlen) {
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;
    
    SWAP(S[i],S[j]);
    
    msg[cnt] = msg[cnt] ^ S[(S[i] + S[j]) % 256];
    cnt++;
  }

  return 0;
}
We can just compile our crypter and then extract the machine code associated to this function. We already know how to extract bytes from a file using dd, we just need to figure out the offset in the file where the function is, and its size. We can get this information in different ways.

We can use objdump:

$ objdump -d crypter-1.4
(...)

00000000000009aa <rc4>:
     9aa:       55                      push   %rbp
     9ab:       48 89 e5                mov    %rsp,%rbp

c88:       c3                      retq

0000000000000c89 <main>:
     c89:       55                      push   %rbp
So, the rc4 function starts at offset 0x9aa and ends at offset 0xc88… That means that it size is 0xc88 - 0x9aa = 735 bytes… Which is quite small and should fit in our test code cave.

Other way to get this information is using readelf:

$ readelf -s crypter-1.4 | grep rc4
    55: 00000000000009aa   735 FUNC    GLOBAL DEFAULT   14 rc4
As you were expecting, we get the same numbers (note that those numbers can be different in your machine, specially if you have modified the crypter and because, your version at this point will be different to the one I’m using right now)…

Now we can use dd to extract the rc4 function in binary form:

dd if=crypter-1.4 skip=$((0x9aa)) bs=1 count=735 > rc4.bin
After that, we can use one of the NASM pseudo-instructions to just insert these machine code in our asm program. They are named pseudo-instructions because they are not machine instructions but instructions aimed to NASM itself. One of these pseudo-instructions is incbin 2 that allows us to include a binary fine at a specific point in our assembler program.

Note: All these values can be different in your system. Just understand the process and run each command getting the right values for your environment.

So, our stub, for the time being, will look like this:

stub_start:
	
	;; Let's create a stack frame 
	push rbp
	mov  rbp, rsp
	;; Save registerrs
	push rdi
	push rsi
	push rdx
	push rax
	
	;; Restore original crypted instructions before decrypting
	sub QWORD [rbp + 0x8], 5 
	mov rax, [rbp + 0x8]
patch1:	
	mov rdx, 0x1122334455667788
	mov QWORD [rax], QWORD rdx

	;; Change memory permissions
	;; Decrypt
	
	
	pop rax	
	pop rdx
	pop rsi
	pop rdi
	pop rbp
	ret
	
_rc4:
	incbin 'rc4.bin'
		
;;;  Data
text_ptr:       dq 0
text_size:      dw 0
rodata_ptr:     dq 0
rodata_size:    dw 0
key:            db "0x00Sec!",0
msg:    db 'Hello World!',0x0a

At this point, we just need to call our new _rc4 function to decode the .text and .rodata segments. I will just do it for the .text segment and I will leave it as an exercise to the reader to also decode .rodata.

Updating the crypter
Let’s get back to the crypter. We need to update it to write at text_ptr and text_size some information that will let the stub find the text segment and decrypt it. As we are targeting PIE binaries, the crypter does not know, at the time of crypting the binary, the runtime address of the relevant sections, so we need to use some differential value with respect to something else we know at run-time.

By now you should know a few ways of solving this problem. Don’t you?.. Anyway, I will just provide the stub offsets w.r.t OEP. This is convenient because we already know the OEP in our stub (we need to restore the instructions there). This is how the crypter loop to crypt the text section will look like when we add this change:

  for (i = 0; i < elf_hdr->e_shnum; i++) {
    name = s_name + sh[i].sh_name;
    printf ("Section %02d [%20s]: Type: %d Flags: %lx | Off: %lx Size: %lx => ",
	    i, name,
	    sh[i].sh_type, sh[i].sh_flags,
	    sh[i].sh_offset, sh[i].sh_size);
    if (!strcmp (name, ".text")) {
      // encrypt section
      rc4 (p + sh[i].sh_offset, sh[i].sh_size, (unsigned char*)key, strlen (key));

      text_ptr = oep - sh[i].sh_offset;
      text_size = sh[i].sh_size;
    }
    else printf ("\n");
  }
Yes, that easy… instead of storing the absolute offset to the .text section, we just store the relative offset with respect to the OEP. Now we just need to write this information in our stub. Let’s get the offset to the data variables we declare in it:

$ readelf -s stub02.o | grep text
     6: 00000000000002ee     0 NOTYPE  LOCAL  DEFAULT    1 text_ptr
     7: 00000000000002f6     0 NOTYPE  LOCAL  DEFAULT    1 text_size
And now we just need to write those values, just after dumping the stub in the code cave…

  // Patch text_ptr and text_size
  *((long*)(p + ccave + 0x2ee)) = text_ptr;
  *((uint32_t*)(p + ccave + 0x2f6)) = text_size;
_Note: You may want to define a couple of constants… it is not good to have magic numbers in your code… but I’ll also leave this as an exercise for you :).

Back to the stub
At this point, we have all the information needed to decode the text segment in our stub, so we can finally call rc4 and decrypt the binary. For that we just need to pass the correct parameters in the usual registers (according to the System V ABI that we are so familiar with at this point). The last thing we have to do is to calculate the real address of the text segment using the OEP and the offset provided by the crypter… Basically we just need to add that offset to the OEP that is stored at [rbp+0x08]…

So… this is what you need to add to your stub… Nooo, just kidding, At this point I’ll give you the whole stub code. We have made too many changes and you may have got lost…


stub_start:
	
	;; Let's create a stack frame 
	push rbp
	mov  rbp, rsp
	
	;; Save registers
	push rdi
	push rsi
	push rdx
	push rax
	
	;; Update return addres to be the OEP
	sub QWORD [rbp + 0x8], 5 
	mov rax, [rbp + 0x8]
	;; Restore the OEP instruction
patch1:	
	mov rdx, 0x1122334455667788
	mov QWORD [rax], QWORD rdx
	
	;; TODO: Change memory permissions 
	;; Decrypt
	;; Decode text segment
	
	mov rax, [rbp + 0x8]	; Get OEP	
 	mov rdi, [rel text_ptr]	; .text ptr will be relative to OEP
 	add rdi, rax
 	lea rsi, [rel key]
 	mov rdx, [rel text_size]
 	mov rcx, 8
		
	call _rc4 ;; _rc4 (rdi, rsi, rdx, rcx);

	;; Restore memory permissions
	
	pop rax	
	pop rdx
	pop rsi
	pop rdi
	pop rbp
	ret       ;; We just return to the OEP
	
_rc4:
	 	incbin 'rc4.bin'
;;;  Data
text_ptr:       dq 0
text_size:      dw 0
rodata_ptr:     dq 0
rodata_size:    dw 0
key:            db "0x00Sec!",0

You can likely save a couple of instructions in the code above, but I preferred to keep it simpler for you to make it more comprehensive.

And just for completeness, this is the final code of the crypter main function (you should be able to extract the stub machine code and store it on the sc variable by yourself:

int main (int argc, char *argv[]) {
  
  if (argc != 2) {
    fprintf (stderr, "Invalid number of parameters\n");
    fprintf (stderr, "Usage: crypter binary\n");
    exit (-1);
  }
  // Open file
  int fd;
  if ((fd = open (argv[1], O_RDWR, 0)) < 0) DIE ("open");
  
  // get size
  struct stat _st;
  if (fstat (fd, &_st) < 0) DIE ("fstat");
  
  // Map file
  unsigned char *p;
  if ((p = mmap (0, _st.st_size, PROT_READ | PROT_WRITE,
		 MAP_SHARED, fd, 0)) == MAP_FAILED) DIE ("mmap");
		 
  // Find code segment
  Elf64_Ehdr *elf_hdr = (Elf64_Ehdr*) p;
  // Sanity checks oimitted
  printf ("Section Table located at : %ld\n", elf_hdr->e_shoff);
  printf ("Section Table entry size : %d\n",  elf_hdr->e_shentsize);
  printf ("Section Table entries    : %d\n",  elf_hdr->e_shnum);  

  int           i;
  Elf64_Shdr    *sh     = (Elf64_Shdr*)(p + elf_hdr->e_shoff) ;
  Elf64_Phdr    *ph     = (Elf64_Phdr*)(p + elf_hdr->e_phoff) ;
  char          *s_name = p + sh[elf_hdr->e_shstrndx].sh_offset;
  Elf64_Addr     oep    = elf_hdr->e_entry;
  char          *key    = "0x00Sec!\0";  // Use 8 characters to make asm simpler.
  char          *name      = NULL;
  long           text_ptr  = 0;
  uint32_t       text_size = 0; 

  for (i = 0; i < elf_hdr->e_shnum; i++) {
    name = s_name + sh[i].sh_name;
    printf ("Section %02d [%20s]: Type: %d Flags: %lx | Off: %lx Size: %lx => ",
	    i, name,
	    sh[i].sh_type, sh[i].sh_flags,
	    sh[i].sh_offset, sh[i].sh_size);
    if (!strcmp (name, ".text")) {
      rc4 (p + sh[i].sh_offset, sh[i].sh_size, (unsigned char*)key, strlen (key));

      text_ptr = oep - sh[i].sh_offset;
      text_size = sh[i].sh_size;
      printf ("%s", " - Crypter!");
    }
    else printf ("\n");
  }

  long ccave = 0;
  int  ccave_size = 0;
  
  for (i = 0; i < elf_hdr->e_phnum; i++) {
    if (ph[i].p_type == PT_LOAD) {
      printf ("PHR %d  flags: %d (offset:%ld size:%ld)\n",
	      i, ph[i].p_flags, ph[i].p_offset, ph[i].p_filesz);
      if (ccave) ccave_size = ph[i].p_offset - ccave;
      if (ph[i].p_flags & PF_X) {
	    ph[i].p_flags |= PF_W; // Add write permissions
	    ccave = ph[i].p_offset + ph[i].p_filesz;
      }
    }
  }

  printf ("Code Cave at %ld size: %ld\n", ccave, ccave_size);

  printf ("Original Entry Point at: %x\n", oep);
  if (ccave_size > sc_len) {
    printf ("Injecting code at %lx\n", ccave);
    for (i = 0; i<sc_len; p[ccave+i]=sc[i],i++);
  }
  
  // Store 8 bytes at current entry point already crypted
  unsigned char op[8], *ep =  p + elf_hdr->e_entry;
  for (i = 0; i < 8; op[i++]= ep[i]);
  
  ep[0] = 0xe8;                     // CALL Opcode
  *((int*)&ep[1]) = ccave- oep - 5; // Inject offset to OEP
  
  // Copy codes into shellcode
  ep = p + ccave + PATCH_OFF + 2; // XXX: You already know how to calculate PATCH_OFF
  for (i =0; i < 8; ep[i] = op[i], i++);
  printf ("Patching instruction at offset: %lx\n", ccave + PATCH_OFF + 2);
  
  // Patch text_ptr and text_size 
  // XXX: YOu also know how to get TEXT_PTR_OFF and TEXT_SZ_OFF
  *((long*)(p + ccave + TEXT_PTR_OFF)) = text_ptr;
  *((uint32_t*)(p + ccave + TEXT_SZ_OFF)) = text_size;
  printf ("Patching text segment at offset: %lx\n", ccave+TEXT_PTR_OFF);
  printf ("Patching text segment size at offset: %lx\n", ccave+TEXT_SZ_OFF);
  munmap (p, _st.st_size); 
  
  close (fd);
  return 0;
} 

Congratulations!!!. You have finished your first crypter.

I will leave the change of the memory permissions as an exercise. You just need to call the mprotect system call… and at this point that shouldn’t be a problem… otherwise you may need to read the series all over again.

Reversing Crypters
You may be thinking that the way I extracted the code from the C version of the crypter and inserted in the asm may look overkill, and it is, however, I wanted to go through this process because that is closer to what you may need to do when analysing a real crypter… You can always go for the dynamic analysis and run the program until it gets decrypted in memory, but sometimes having the crypt routine isolated can be handy.

Actually, for our current crypter implementation, the dynamical analysis is not that straightforward. I will share with you a few notes on how I was debugging the crypter while building it.

The first issue I had already mentioned in the last instalment. The stub code is added out of the section, in the code cave, and therefore, neither gdb nor objdump can find it.

In order to get to the stub code for debugging it. First set a break point at _start using the command b _start. And then run the program with the r command:

(gdb) b _start
Breakpoint 1 at 0x8a0
(gdb) r
Starting program: /tmp/k1

Breakpoint 1, 0x00005555555548a0 in _start ()
(gdb) disassemble _start
Dump of assembler code for function _start:
=> 0x00005555555548a0 <+0>:     callq  0x555555555780
   0x00005555555548a5 <+5>:     rex.RXB add (%r10),%r12b
   0x00005555555548a8 <+8>:     jmp    0x555555554905 <deregister_tm_clones+53>
These sequence of commands will bring us to the call to our stub. Now we just need to jump in the stub using the single instruction command ,si. However gdb will not recognise that as a function and we cannot just disassemble the stub. We can do a couple of things:

Dump the memory as instructions

  (gdb) x/10i 0x0000555555555780
  => 0x555555555780:      push   %rbp
     0x555555555781:      mov    %rsp,%rbp
     0x555555555784:      push   %rdi
     0x555555555785:      push   %rsi
     0x555555555786:      push   %rdx
     0x555555555787:      push   %rcx
     0x555555555788:      push   %rbx
     0x555555555789:      push   %rax
     0x55555555578a:      push   %r8
     0x55555555578c:      push   %r9
Use the layout command. layout regs will split the screen showing at the top the registers and below the assembler code of the current and next instructions.

The next point, took me a while to figure out. At least in my box, looks like gdb uses a traditional breakpoint for _start. The one we set above to get into the call to the stub. A traditional breakpoint consists on writing a int 3 (opcode 0xcc)in the address we want the program flow interrupted and the control returned to our debugger. int 3 is just one byte long so we can place it anywhere. You can read a little bit about how it works in the article about the IBI Crypter 5 here at 0x00sec.

Anyway, gdb writes this 0xcc opcode at the _start position, but that fact makes the restore of the original opcodes we do later in our stub fail. I was very confused seen how all the bytes except the first one where restored until I realised that it could be related to the break point… So, just after stopping at _start delete the breakpoint with the command d 1, so the original bytes of _start can be successfully restored.

Hope this tips helps you in your own projects!

RC4 in assembler
Our crypter works pretty well and it is not that big. The rc4 function generated by my compiler (without any special optimisation) is 735 bytes… We can make it shorter with a native asm implementation.

Before getting into the gory details, let’s quickly remember how the RC4 algorithm implementation looked in C:

  // KSA: Key-Schedulling Algorithm
  for (i = 0; i < 255; S[i] = i,i++);
    
  for (j = 0, i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % klen] ) % 256;
    SWAP(S[i],S[j]);
  }
    // Encoding
  i = j = 0;
  while (cnt < mlen) {
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;
    SWAP(S[i],S[j]);
    
    msg1[cnt++] = msg[cnt] ^ S[(S[i] + S[j]) % 256];
  }
So, the first thing we need to do is the Key-Scheduling Algorithm that requires two loops and a local array to store our permutation matrix S. Let’s create a stack frame and allocate the memory for the S vector:

    EQU     S 256
rc4:
	push rbp
	mov  rbp, rsp
	push r13
	sub  rsp, S
	mov r13, rdx
	;; KSA
	;; Actual Message de/crypt
	pop r13
	leave    ;; retore RBP and RSP
	ret
So far so good. In addition to the stack frame and the allocation of S, we just save r13 that we will use for storing the third parameter, that in this case is the length of the message. This was just convenient, but you can just store that value in the stack allocating a bit more space. You already know how to do that. Of course we need to restore it before leaving the function.

NOTE:I changed the order of the parameters for the assembler version, with regards to the C version. I used first and second parameters for the message and key pointers respectively. Those parameters goes into si and diand are convenients. So third parameter is the size of the message and forth is the size of the key that, for this case I have fixed to 8 for convenience.

That is it. Now it is time to do the first KSA initialisation loop:

;    for (i = 0; i < 255; S[i] = i,i++);
	lea r8, [rbp - S]     ;; r8 points to the S matrix
	mov rax, 256          ;; We will loop for 256 values
KSA0:
	mov [r8 + rax], al     ;; S[al] = al;
	dec rax                ;; al--;
	jnz KSA0
This loop was easy, right?. We just counted down instead of up, just to save a comparison for the last jump. Now let’s implement the shuffle stage of the KSA. This is implemented in C by the following loop:

  for (j = 0, i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % klen] ) % 256;
    SWAP(S[i],S[j]);
  }
Here we are going to use a couple of tricks to get rid of the module operators. The module operator % (we had already talked about it), is not easy to implement in the general case, however, when the divisor is a power of two, we can just substitute it by an AND operation. As we said when we introduced the rc4 algorithm we are very grateful to Mr Rivest for making the algorithm byte friendly… that means that everything is related to the size of a byte and that is where the %256 module above comes from.

For that module (% 256), when working on assembler… we can just use 8 bit registers and forget about the module… And that is what we are going to do. Well, you cannot always do that, but for this specific case it will work just fine.

For the key… well, we are going to chose a key that is 8 characters long. Doing that, the % klen in the code above can just be substituted by a AND KEY_MASK where KEY_MASK is 0x07.

Taking this into account, the loop can be implemented in asm like this:

KEY_MASK  EQU     0x07

;; 2. suffle
	xor rdx, rdx		; key counter (i % KEY_LEN) rdx
	xor rbx,rbx		    ; j counter
	mov r9, key		    ; Key pointer
	xor rcx,rcx		    ; i counter	
KSA1:
	;; calculate index
	and  rdx, KEY_MASK 	; i % KEY_LEN
	mov  al, [r8 + rcx]	; S[i]
	add  al, [r9 + rdx]	; S[i] + key [i%KEY_LEN]
	add  bl, al		    ; j = j + S[i] + key [ i % KEY_LEN]
	
	mov  r11b, [r8 + rcx]
	mov  r12b, [r8 + rbx]
	mov  [r8+rcx], r12b
	mov  [r8+rbx], r11b 	; swap (S[i],S[j])
	
	inc  rcx
	mov  rdx, rcx
	cmp  rcx, 256
	jnz  KSA1
Note: In this case we cannot do the loop counting down as the resulting permutation matrix will be different due to the swap instruction. Do you see the cmp towards the end? the one we saved in the previuswsloop…

As you can see, with the exception of the key, we have just got rid of all the module operators that we used in the C code… actually we could had implemented this way in C. Also note the use of the 8 bytes registers al, bl , r11b and r12b.

For intel platforms the low byte of the historical 16bits registers (AX, BX, CX, DX,…) is named with an l and the high byte is named with a ‘h’… and you should be able to figure out why :slight_smile: . This way, the 16bits register ‘AX’ can be accessed using the register AH for the high byte, and AL for the low byte.

For the new registers introduced in the 64bits architecture, the naming is different. A b represents the last byte of the register, a ‘w’ to access the last 16 bits word and a d to access the last 32 bits. Therefore, r11b and r12b are the last byte of those registers.

Time to crypt
Now we can implement the crypt loop. If you had understood the initialisation code, this part doesn’t have any further surprises and should be pretty straightforward to understand… we just point now to the message instead of to the key and slightly change some of the operations:

	;; --------------------------------------------
	;; Encrypt
	;; -----------------------------------
	mov r9, rdi		; Now r9 points to the message 
	xor rcx,rcx		; i =  0
	xor rdx, rdx	; j =0
	xor r10, r10	; cnt = 0;
	xor rax,rax
ENC0:
	;;  i = (i + 1) % 256;
	inc cl

	;; j = (j + S[i]) % 256
	add dl,[r8 + rcx]
	
	;;  SWAP (s[i], S[j])
	mov  r11b, [r8 + rcx]
	mov  r12b, [r8 + rdx]
	mov  [r8+rcx], r12b
	mov  [r8+rdx], r11b 
	
	;; tmp = S[S[i]+S[j])%256]
	mov al, [r8 + rcx]
	add al, [r8 + rdx] 		;; S[i]+S[j])%256

	
	mov bl, [r8 + rax]
	xor [r9+r10], bl	;; msg[cnt] ^= S[S[i]+S[j])%256]

	inc r10
	cmp r10, r13
	jnz ENC0
Be free to comment in case there is something not clear, but if you have understood the concept of working with the 8 bits registers there is not much more to say.

Now we can compile our new stub…

$ nasm -f elf64 -o stub03.o stub03.asm
$ readelf -S stub03.o | grep -A1 .text
  [ 1] .text             PROGBITS         0000000000000000  00000180
       0000000000000131  0000000000000000  AX       0     0     16
This gives us a 0x131 (305) bytes long stub, that is less than half of the C version we extracted from the C code. You can save a few more bytes with some changes in the code, but not much more.

Trying the crypter
At this point I tried my crypter and it failed miserably… that is the reason this instalment took so long to be released, it took me a while to figure out the problem. I had to implement quite some debug code in the stub itself.

So, what happened?. Everything worked as expected but only part of the .text segment was actually decoded. After some debugging I found when that happened and after some more debugging I found that the permutation matrix changed in the assembler version… So I tried to find out what was wrong with the assembler… but as you can see, the code for the rc4 algorithm is pretty basic, and I couldn’t find any issue with it… And that was because the issue was in the C code.

If you remember previous instalments, I used a macro to implement the SWAP of two bytes that looked like this:

#define SWAP(a,b) a += b; b= a -b; a-=b;
The problem happen when we have to swap the same entry in the matrix… calling something like SWAP(S[i],S[i]), because in this case, when we modify a we are also modifying b and therefore all the calculations goes wrong… Just change all bs to as in the expression above and you will see that you get two 0s.

When we extracted the code from the C program, the algorithm had the same flaw (in the crypter and in the stub) and therefore it was actually encoding and decoding the sequences all right. The consequence of the bug above is that at some point we have two zeros in the permutation matrix… the output would be a bit less random, but it still looks like crypted code.

But now that we wrote the asm directly and use temporal registers to swap the values in the permutation matrix the algorithm produced a different permutation matrix than the C version… but that happens just after a while… which made this bug tricky to find and debug.

Anyway, in order to fix this, I changed the C macro to:

#define SWAP(x, y) do { typeof(x) tmp = x; x = y; y = tmp; } while (0)
and everything started working like a charm. That is the basic swap that uses a temporal variable.

Why the do... while
You may be wondering why the swap code is surrounded by that useless while loop. Useless because the condition is never true. Well, writing macros may be tricky… Imagine that you need to write code like this:

if (some_condition) SWAP (i,j);
Without the while loop, the pre-processor will expand the macro to this:

if (some_condition) typeof(x) tmp = x; x = y; y = tmp; 
Do you see the problem?.. No?.. Let’s re-order the code

if (some_condition) 
    typeof(x) tmp = x; 
x = y; y = tmp; 
Now it may be clear. You can just use the brackets… but in that case we will get an extra semicolon after the macro expansion:

#define SWAP(x, y) { typeof(x) tmp = x; x = y; y = tmp; }
if (some_condition) SWAP (i,j);
This will expand to:

if (some_condition)
{
  typeof(x) tmp = x; x = y; y = tmp; 
};   // <====== See this colon here?
You see the semicolon?.. In that example is fine… but if we had an else following that if statement we will get a compilation error. Using the while loop we avoid all these problems:

if (some_condition)
  do { 
    typeof(x) tmp = x; x = y; y = tmp; 
	} while (0) ; // <== Semicolon here is OK
else // <== Else here is also fine
Note: Yes, sure… we should also had used the while loop with the original macro… I just didn’t wanted to introduce too many concepts simultaneously.

Further Steps
I will finish this mini series about crypters here. There are a few things I haven’t completely cover, but I believe I have given you all the tools to solve those issues by yourself. Trying to solve things by yourself is key to the learning process, if you do not believe me just try it by yourself. What you learnt that way will be engraved in stone in your brain. Said that, these are the further steps you can follow to complete your PPCC or PPCC is Pico’s Cypter Certification :).

Compile your rc4 C routing into an ELF object code and link it to the asm. You will need to deal with relocations. That is something we haven’t cover, but, by now, you should be able to bring up the ELF specification, and go through it to figure out how to find that information and how to applied it.
The patching mechanism described here doesn’t work with certain binaries. I just try, for instance with xeyes in my system and it failed… That will require some investigation in your side
In general, you may need to patch more sections in your binary… you can just repeat the code many times or go creative and practice some assembly coding.
Conclusion
This instalment completes this miniseries on crypters. We have gone through the insights of the ELF format, find holes to inject code and actually injecting it. We learnt a little bit about cryptography and implemented a real cryptography algorithm in assembly. We have also learnt how to extract functions from binary programs and use them in our own code. As a result we have got a working crypter that uses a 300 bytes stub and a not trivial algorithm. Not bad right?
