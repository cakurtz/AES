# Advanced Encryption Standard (AES)

[Description]
I implemented this assignment in 1 java file called AES.java. The program intakes the command line arguments and decides whether this is an encryption or decryption. If it is to encrypt the file, it parses line by line to encrypt each line. There are 14 rounds in a 256-bit key implementation and each round has 4 operations except the first, with an additional addRoundKey, and the last, which omits the mixColumns. The reverse happens with decryption. To compile the program, use "javac *.java". To run the program, use "java AES <option> <keyFile> <inputFile>".
I also included an optional third argument for debugging. It prints out the key expansion and the string in hex of the state after each operation in the round. It is very similar to Dr. Young's output. To run this version, use "java AES <option> <keyFile> <inputFile> debug".

[Finish]
I finished the whole assignment. I ended up using Dr. Young's mixColumns implementation as I struggled with that portion. All testing was done on the third floor lab machines.

[Test Case 1]

[Command line]
java AES e keyFile inputFile
java Aes d keyFile inputFile.enc
[Timing Information]
Encryption: 3.3kB/127ms = 0.0033MB/127ms = 0.00002598 MB/ms
Decryption: 3.3kB/113ms = 0.0033MB/113ms = 0.0000292 MB/ms
[Input Filenames]
key - keyFile
encryption - inputFile
decryption - inputFile.enc
[Output Filenames]
encryption - inputFile.enc
decryption - inputFile.enc.dec



[Test Case 2]

[Command line]
java AES e keyFile inputFile2
java Aes d keyFile inputFile2.enc
[Timing Information]
Encryption: 6.6kB/203ms = 0.0066MB/203ms = 0.0000325 MB/ms
Decryption: 6.6kB/195ms = 0.0066MB/195ms = 0.0000338 MB/ms
[Input Filenames]
key - keyFile
encryption - inputFile2
decryption - inputFile2.enc
[Output Filenames]
encryption - inputFile2.enc
decryption - inputFile2.enc.dec



[Test Case 3]

[Command line]
java AES e keyFile2 inputFile3
java Aes d keyFile2 inputFile3.enc
[Timing Information]
Encryption: 3.3kB/126ms = 0.0033MB/126ms = 0.00002619 MB/ms
Decryption: 3.3kB/111ms = 0.0033MB/111ms = 0.00002972 MB/ms
[Input Filenames]
key - keyFile2
encryption - inputFile3
decryption - inputFile3.enc
[Output Filenames]
encryption - inputFile3.enc
decryption - inputFile3.enc.dec


[Test Case 4]

[Command line]
java AES e keyFile2 inputFile4
java Aes d keyFile2 inputFile4.enc
[Timing Information]
Encryption: 8.6kB/248ms = 0.0086MB/248ms = 0.00003467 MB/ms
Decryption: 8.6kB/245ms = 0.0086MB/245ms = 0.0000351 MB/ms
[Input Filenames]
encryption - inputFile4
decryption - inputFile4.enc
[Output Filenames]
encryption - inputFile4.enc
decryption - inputFile4.enc.dec
