# r4ge

A rizin Plugin to perform symbolic execution with a simple 
macro call.
Internally it uses angr as execution engine.
The Usage is possible with and without debugger, dynamic and 
static analysis mode.

## installation
To "install" it just create r2-macros in your .rizinrc file
with the according path to the r4ge files.

Requirements are of course angr and rizin and also termcolor which is used
for colored printing.

##### needed macros:

main plugin file, performs static and dynamic analysis
```sh
(r4ge; #!pipe python /home/niku/SharedWin/GitRepos/r4ge/src/r4ge.py)
```
mark a specific memory region as symbolic (addr: start address, bytes: how many bytes, name: name
the variable)
```sh
(markMemSymbolic addr bytes name; #!pipe python /pathToFile/createVariable.py symb $0 $1 $2)
```

create hooks in r2 and patch function calls or other statements (syntax of the instructions: rax=0x4
or rax=0x4;rbx=0x10)
```sh
(addHook addr instructions bytes comment; #!pipe python /pathToFile/createVariable.py hook $0 $1 $2 $3)
```

create asserts to check register values during exploration (syntax of the instructions: rax==0x3 or
rax#=0x3;rax<=0x10) Note: # is used instead of >, cause r2 uses > as pipe operator.
```sh
(addAssert addr assertions comment; #!pipe python3 /pathToFile/createVariable.py assert $0 $1 $2)
```

it is also possible to search for a specific string in stdout, just call the makro below. this will
ignore find flags, but will consider hooks and asserts. (r2 has many special characters so it may not
be possible to put arbitrary strings in the makro but you can modify the r2-variable by your own)
```sh
(checkStdout content;  #!pipe python3 /pathToFile/createVariable.py checkstdout $0)
```

create an angr script out of the current r2 session
```sh
(createScript name; #!pipe python3 /pathToFile/createScript.py $0)
```

call a function and specifiy the return value (currently in development mode)
```sh
(callFunction retval; #!pipe python3 /pathToFile/callFunction.py $0)
```

## usage

The dynamic mode will print the concretized symbolic memory if it found a path, 
the static mode will open an IPython shell in r2 and you will have to concretize the memory
by yourself.

In r2 just create the flags with the name: r4ge.start (only needed in static mode), r4ge.find,
r4ge.avoidx (where x is a increasing number, it is not possible in r2 to create flags with the same
name)
After the flag creation, create Hooks or Asserts if you need one and afterwards just call the r4ge
macro.

![usage image](/doc/usage_image.png)

short tutorial: https://asciinema.org/a/155856

## Questions
do not hesitate to ask or write us an email ;)

## Updates

update 20.10.2021
- moved to rizin (minimal support only)

update 10.06.2021, more will come :)
- ported to python3.8 and angr 9.0.7833

## Example

[![r4ge example](https://asciinema.org/a/418791.svg)](https://asciinema.org/a/418791)
