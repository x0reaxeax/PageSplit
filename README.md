# Shellcode PageSplit

### Splitting and executing shellcode across multiple pages

Target shellcode is a PopCalc by [Bobby Cooke (boku)](https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode).  
<br />
The purpose of this PoC is to demonstrate signature evasion by allocating multiple (whole) pages for a relatively small encoded shellcode, splitting, and executing it across these pages.  
Each part of the shellcode is decoded only when about to be executed and free'd immediately after.  

The main caveat are RIP-relative `call`s and `jmp`s, which this shellcode has only two instances of (IIRC), however, this poses a limitation on the block size the shellcode can be split into.  
Of course, as this is a proof-of-concept, these limitations are not the priority.  

### Preview
![Preview](https://i.imgur.com/MV8rcGy.png)

<br />
<br />

*This project is licensed under the MIT license. Copyrights are respective of each contributor listed at the beginning of each definition file.*
